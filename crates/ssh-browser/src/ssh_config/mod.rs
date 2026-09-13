//! The hosts this machine's ssh already knows how to reach.
//!
//! Everything here reads what OpenSSH reads, and nothing here decides how to connect.
//! The transport is `ssh <host> -s sftp`, so authentication, `ProxyJump`, `User`, `Port`
//! and the rest are OpenSSH's to resolve and this daemon's only job is to name the host.
//! Reimplementing any of that would produce a second, worse copy of a file the user has
//! already got right.
//!
//! Two separate things live here for that reason. Parsing the file answers "which hosts
//! exist", which is a question about names and is worth doing locally. Answering "what
//! does this host resolve to" is `ssh -G`'s job, because the resolution rules — first
//! match wins, `Match` blocks, `Include`, canonicalisation — are not something to
//! reimplement for the sake of a line in a popup.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::origin::guard;

/// How deep `Include` is followed before giving up, matching OpenSSH's own limit.
const MAX_INCLUDE_DEPTH: usize = 16;

/// A host named in ssh_config, and the alias it would be served under.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Host {
    /// The name as written in the file, which is what `ssh` is invoked with.
    ///
    /// Kept exactly as written. `Host Panza` is reached as `Panza`, and lowercasing what
    /// gets passed to ssh would be this daemon second-guessing a file it does not own.
    pub host: String,
    /// The same name as a hostname label, which is what an alias has to be.
    pub alias: String,
}

/// A host that exists but cannot be served, and why.
///
/// Carried rather than dropped. A host missing from the list with no explanation reads
/// as this daemon having failed to find it, which is a different problem with a
/// different fix.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Unusable {
    pub host: String,
    pub why: String,
}

/// What a parse found: the hosts that can be served, and the ones that cannot.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Found {
    pub hosts: Vec<Host>,
    pub unusable: Vec<Unusable>,
}

/// `~/.ssh/config`, wherever this user's home is.
pub fn default_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".ssh").join("config"))
}

/// Read the user's ssh_config and every file it includes.
///
/// A missing file is an empty answer rather than an error: not having an ssh_config is
/// an ordinary state, and it is the same answer as having one that names no hosts.
pub fn read() -> Result<Found> {
    let Some(path) = default_path() else {
        return Ok(Found::default());
    };
    read_from(&path)
}

/// The same, from a named file. Split out so tests have a way in.
pub fn read_from(path: &Path) -> Result<Found> {
    if !path.exists() {
        return Ok(Found::default());
    }
    // `Include` is resolved against the directory the top-level file lives in, which is
    // `~/.ssh` for the user config. OpenSSH resolves relative includes against that
    // directory rather than against the including file, so nesting does not shift it.
    let root = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut text = String::new();
    gather(path, &root, 0, &mut text)?;
    Ok(parse(&text))
}

/// Append a file's lines, following `Include` as it goes.
fn gather(path: &Path, root: &Path, depth: usize, out: &mut String) -> Result<()> {
    if depth > MAX_INCLUDE_DEPTH {
        // Refused rather than silently truncated, because an include loop that quietly
        // stopped producing hosts would look exactly like a config that did not name
        // them.
        anyhow::bail!(
            "ssh_config includes nest more than {MAX_INCLUDE_DEPTH} deep at {}",
            path.display()
        );
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    for line in text.lines() {
        match include_target(line) {
            Some(pattern) => {
                for file in expand(pattern, root) {
                    // A named include that is not there is skipped, as OpenSSH skips it.
                    // `Include config.d/*` matching nothing is the ordinary state of a
                    // machine that has not made one yet.
                    if file.is_file() {
                        gather(&file, root, depth + 1, out)?;
                    }
                }
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    Ok(())
}

/// The argument of an `Include` line, if this is one.
fn include_target(line: &str) -> Option<&str> {
    let (keyword, rest) = keyword_and_rest(line)?;
    keyword.eq_ignore_ascii_case("include").then_some(rest)
}

/// Split a config line into its keyword and the rest.
///
/// ssh_config accepts `Key value`, `Key=value` and any amount of surrounding space, so
/// the split has to handle all three. Comments and blank lines answer `None`.
fn keyword_and_rest(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_ascii_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (keyword, rest) = line.split_at(end);
    Some((keyword, rest.trim_start_matches(['=', ' ', '\t']).trim()))
}

/// Expand one `Include` argument into the files it names.
///
/// Only the final component may contain a wildcard, which is what every real config
/// does: `Include config.d/*`.
fn expand(pattern: &str, root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for word in pattern.split_ascii_whitespace() {
        let word = word.trim_matches('"');
        let resolved = if let Some(rest) = word.strip_prefix("~/") {
            match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
                Some(home) => PathBuf::from(home).join(rest),
                None => continue,
            }
        } else if Path::new(word).is_absolute() {
            PathBuf::from(word)
        } else {
            root.join(word)
        };

        let Some(last) = resolved.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !last.contains(['*', '?']) {
            out.push(resolved);
            continue;
        }
        let Some(dir) = resolved.parent() else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        // Sorted, so that a config split across several files produces the same ordering
        // every run. Directory order is not defined and OpenSSH sorts for the same reason.
        let mut matched: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|name| glob_matches(last, name))
            })
            .map(|e| e.path())
            .collect();
        matched.sort();
        out.extend(matched);
    }
    out
}

/// `*` and `?` against one filename component, which is all ssh_config's includes use.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    // The two-index walk with a remembered star, which is linear rather than the
    // exponential the obvious recursion gives on a pattern full of stars.
    let (mut pi, mut ni) = (0, 0);
    let (mut star, mut resume) = (None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            resume += 1;
            ni = resume;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// The hosts named by an ssh_config's text.
///
/// Only concrete names. A pattern is a rule for matching hosts, not a host: `Host *`
/// sets defaults for everything and names nothing, and serving an alias called `*` is
/// not a thing that could work. Negations are patterns too.
///
/// Order is the file's order, and the first spelling of a duplicate wins, because that
/// is the one OpenSSH's first-match-wins resolution will use.
pub fn parse(text: &str) -> Found {
    let mut found = Found::default();
    let mut seen: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some((keyword, rest)) = keyword_and_rest(line) else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("host") {
            continue;
        }
        for name in rest.split_ascii_whitespace() {
            let name = name.trim_matches('"');
            if name.is_empty() || name.contains(['*', '?']) || name.starts_with('!') {
                continue;
            }
            // The alias becomes a hostname label and hostnames are case-insensitive, so
            // `Host Panza` is served as `panza`. Lowercasing is the whole transformation:
            // anything more would be this daemon inventing a name for a host the user has
            // already named.
            let alias = name.to_ascii_lowercase();
            if seen.iter().any(|s| s == &alias) {
                continue;
            }
            seen.push(alias.clone());
            if guard::is_label(&alias) {
                found.hosts.push(Host {
                    host: name.to_string(),
                    alias,
                });
            } else {
                found.unusable.push(Unusable {
                    host: name.to_string(),
                    why: "not usable as a hostname label: give it an alias in the config file"
                        .to_string(),
                });
            }
        }
    }
    found
}

/// What OpenSSH resolves a host to, for showing beside it.
///
/// Every field is whatever `ssh -G` said, which is the only answer that matches what the
/// transport will actually do. Parsing the config for these would mean reimplementing
/// first-match-wins, `Match` blocks and canonicalisation, and being subtly wrong about a
/// host the user can see is configured correctly.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Settings {
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    #[serde(rename = "proxyJump")]
    pub proxy_jump: Option<String>,
}

/// Read `ssh -G` output into the handful of fields worth showing.
///
/// Unknown keys are ignored rather than refused: `ssh -G` prints every option OpenSSH
/// has, the list grows with each release, and none of the rest is this daemon's business.
pub fn parse_settings(text: &str) -> Settings {
    let mut s = Settings::default();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once(' ') else {
            continue;
        };
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "user" => s.user = Some(value.to_string()),
            "hostname" => s.hostname = Some(value.to_string()),
            "port" => s.port = value.parse().ok(),
            // `ssh -G` prints the literal word for "no jump host", and showing that
            // beside a host would suggest a jump host called "none".
            "proxyjump" if !value.eq_ignore_ascii_case("none") => {
                s.proxy_jump = Some(value.to_string());
            }
            _ => {}
        }
    }
    s
}

/// Ask OpenSSH what a host resolves to.
pub async fn describe(host: &str) -> Result<Settings> {
    let out = tokio::process::Command::new("ssh")
        .arg("-G")
        .arg(host)
        .output()
        .await
        .with_context(|| format!("run ssh -G {host}"))?;
    // stdout is read even on a non-zero exit. `ssh -G` reports what it could resolve and
    // then complains, and the partial answer is more useful than none.
    Ok(parse_settings(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hosts_of_a_real_looking_config_are_found_in_order() {
        let found = parse(
            "Host Panza\n  HostName panza.example\n\nHost yukawa-front\n  ProxyJump yukawa-mercury\n",
        );
        assert_eq!(
            found.hosts,
            vec![
                Host {
                    host: "Panza".to_string(),
                    alias: "panza".to_string()
                },
                Host {
                    host: "yukawa-front".to_string(),
                    alias: "yukawa-front".to_string()
                },
            ]
        );
        assert!(found.unusable.is_empty());
    }

    /// A pattern is a rule for matching hosts, not a host. `Host *` is how nearly every
    /// config sets its defaults, so serving it would put an alias called `*` in front of
    /// whatever the first stanza happened to be.
    #[test]
    fn patterns_are_not_hosts() {
        let found = parse("Host *\n  ForwardAgent yes\nHost *.example.com\nHost !bad ok\n");
        assert_eq!(
            found.hosts,
            vec![Host {
                host: "ok".to_string(),
                alias: "ok".to_string()
            }]
        );
    }

    /// One stanza can name several hosts, and they are separate hosts.
    #[test]
    fn one_line_can_name_several_hosts() {
        let found = parse("Host alpha beta gamma\n");
        let aliases: Vec<&str> = found.hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["alpha", "beta", "gamma"]);
    }

    /// ssh_config's own spelling latitude: `Key=value`, leading space, comments.
    #[test]
    fn the_odd_spellings_ssh_config_allows_are_understood() {
        let found = parse("# a comment\n\n   host=Odd\n\tHOST   Other\n");
        let aliases: Vec<&str> = found.hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["odd", "other"]);
    }

    /// Hostnames are case-insensitive, so these are one host, and the name ssh is
    /// invoked with is the first spelling rather than the last.
    #[test]
    fn a_host_named_twice_in_different_cases_is_one_alias() {
        let found = parse("Host Panza\nHost panza\n");
        assert_eq!(found.hosts.len(), 1);
        assert_eq!(found.hosts[0].host, "Panza");
    }

    /// Named rather than dropped, so the absence has a reason attached to it.
    #[test]
    fn a_host_that_cannot_be_a_label_is_reported_rather_than_dropped() {
        let found = parse("Host build.example.com\nHost fine\n");
        let aliases: Vec<&str> = found.hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["fine"]);
        assert_eq!(found.unusable.len(), 1);
        assert_eq!(found.unusable[0].host, "build.example.com");
    }

    #[test]
    fn ssh_dash_g_output_is_read_for_the_fields_worth_showing() {
        let s = parse_settings(
            "user souta\nhostname 10.0.0.2\nport 2222\nproxyjump bastion\nforwardagent yes\n",
        );
        assert_eq!(s.user.as_deref(), Some("souta"));
        assert_eq!(s.hostname.as_deref(), Some("10.0.0.2"));
        assert_eq!(s.port, Some(2222));
        assert_eq!(s.proxy_jump.as_deref(), Some("bastion"));
    }

    /// `ssh -G` prints the word rather than omitting the key, and showing it would
    /// suggest a jump host called "none".
    #[test]
    fn proxyjump_none_is_no_proxy_jump() {
        assert_eq!(parse_settings("proxyjump none\n").proxy_jump, None);
    }

    #[test]
    fn globs_match_the_way_include_needs() {
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("*.conf", "work.conf"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "ac"));
        assert!(!glob_matches("*.conf", "conf.bak"));
        assert!(glob_matches("*a*b*", "xxayybzz"));
    }

    #[test]
    fn include_pulls_in_another_file() {
        let dir = std::env::temp_dir().join(format!("ssh-browser-inc-{}", std::process::id()));
        let sub = dir.join("config.d");
        std::fs::create_dir_all(&sub).expect("temp dirs");
        std::fs::write(sub.join("10-work.conf"), "Host from-include\n").expect("write include");
        std::fs::write(dir.join("config"), "Host direct\nInclude config.d/*\n").expect("write");

        let found = read_from(&dir.join("config")).expect("reads");
        let aliases: Vec<&str> = found.hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["direct", "from-include"]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
