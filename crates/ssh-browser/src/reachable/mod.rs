//! Which hosts are opened without being asked for, every run.
//!
//! Without this, a host from `ssh_config` is reachable only after somebody opens it from the
//! dashboard, and they have to do that again after every restart. Enabled means the daemon
//! opens it for them, so `http://<name>.<suffix>/` simply works.
//!
//! **Enabled means open, not "openable on request".** The tempting version is to connect when
//! a request for an unopened host arrives — but every request to an alias origin arrives
//! through the proxy, and a page can cause one of those by writing `<img src>`. So that version
//! hands any web page the ability to start ssh sessions, and the timing difference between
//! connecting and refusing tells it which hosts you have.
//!
//! The obvious defence does not exist: `Sec-Fetch-Dest` would separate a navigation from a
//! subresource, and **Chromium sends no `Sec-Fetch-*` header at all on a proxied request**.
//! Measured, not assumed — every request through the PAC arrives with none of them, while the
//! same browser sends them to `127.0.0.1` directly. So the daemon cannot tell the two apart,
//! and the rule stays what it already was: a session is opened by the daemon itself at startup
//! or by a control call carrying the token, and by nothing else.
//!
//! **Nothing here records how to reach a host.** Only its name, which is a `Host` in
//! `ssh_config`; the account, the port and the jump host stay there. That keeps the interesting
//! details in one file rather than two, and it is also what makes this set uninteresting to
//! leak: the name is already in the URL you typed.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Result, bail};

/// One host opened without being asked for, and where it is rooted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    /// `None` for the remote's home directory, resolved when it is first connected.
    pub base: Option<String>,
    pub enabled: bool,
}

/// Every host anybody has an opinion about, by name.
///
/// A map rather than a list because the question asked of it is always about one name, and
/// because the order it iterates in is then the order the startup banner prints.
#[derive(Debug, Default, Clone)]
pub struct Set {
    hosts: BTreeMap<String, Host>,
}

impl Set {
    /// The configured hosts, with any remembered changes of mind applied over them.
    pub fn new(configured: Vec<Host>) -> Self {
        let mut hosts: BTreeMap<String, Host> = configured
            .into_iter()
            .map(|h| (h.name.clone(), h))
            .collect();
        // Applied over the file rather than replacing it. The file says where a host is
        // rooted; this only ever says whether it is on. So a host turned off from the
        // dashboard and turned back on later is still rooted where the file put it.
        for (name, enabled) in remembered() {
            if let Some(host) = hosts.get_mut(&name) {
                host.enabled = enabled;
            } else if enabled {
                // Enabled from the dashboard for a host the file never mentioned, which is the
                // ordinary way to turn one on: pick it out of the list and click.
                hosts.insert(
                    name.clone(),
                    Host {
                        name,
                        base: None,
                        enabled: true,
                    },
                );
            }
        }
        Self { hosts }
    }

    /// This host, if it is enabled.
    ///
    /// Disabled reads the same as absent, which is what lets a caller treat "turned off" and
    /// "never mentioned" alike without writing the distinction down anywhere.
    pub fn get(&self, name: &str) -> Option<&Host> {
        self.hosts.get(name).filter(|h| h.enabled)
    }

    /// Every enabled host, for the daemon to open at startup.
    pub fn enabled(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values().filter(|h| h.enabled)
    }

    /// Turn one on or off.
    ///
    /// Remembering it is a separate call: a state directory that cannot be written must not
    /// undo a change the reader can already see working.
    pub fn set(&mut self, name: &str, enabled: bool, base: Option<String>) {
        self.hosts
            .entry(name.to_string())
            .and_modify(|h| h.enabled = enabled)
            .or_insert_with(|| Host {
                name: name.to_string(),
                base,
                enabled,
            });
    }

    /// What to write down, so the next run starts where this one left off.
    fn to_text(&self) -> String {
        let mut out = String::new();
        for host in self.hosts.values() {
            out.push(if host.enabled { '+' } else { '-' });
            out.push_str(&host.name);
            out.push('\n');
        }
        out
    }
}

/// Where the enabled set is remembered between runs.
///
/// Beside the token, not in the user's `config.toml`. That file is hand-written and carries
/// their comments, and a daemon that rewrote it would eventually lose one. The config file
/// still sets the starting value; this records a later change of mind — the same arrangement
/// the theme uses, for the same reason.
fn stored_path() -> Option<PathBuf> {
    Some(crate::control::state_dir()?.join("enabled"))
}

/// One host per line: `+name` on, `-name` off.
///
/// Off is written out rather than left implicit, because a host the config file turns on has to
/// be turnable off again — and "absent" cannot say that.
fn remembered() -> Vec<(String, bool)> {
    let Some(path) = stored_path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<(String, bool)> {
    let line = line.trim();
    let enabled = match line.chars().next()? {
        '+' => true,
        '-' => false,
        // Neither form means a future version or a damaged file. Skipped rather than guessed
        // at: a guess here turns a host on, or off, without being asked.
        _ => return None,
    };
    let name = line[1..].trim();
    (!name.is_empty()).then(|| (name.to_string(), enabled))
}

/// Remember the set, and say where it went.
pub fn remember(set: &Set) -> Result<PathBuf> {
    let path = match stored_path() {
        Some(path) => path,
        None => bail!("no directory to remember which hosts are reachable in"),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, set.to_text())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_host_reads_exactly_like_one_that_is_not_there() {
        let mut set = Set::default();
        set.set("off", false, None);
        assert!(set.get("off").is_none());
        assert!(set.get("never-configured").is_none());
    }

    /// The whole reason `-name` is written down rather than left out: a host the config file
    /// turns on has to be turnable off, and absence cannot say that.
    #[test]
    fn off_survives_a_round_trip_through_the_file_format() {
        let mut set = Set::default();
        set.set("on", true, None);
        set.set("off", false, None);
        let lines: Vec<(String, bool)> = set.to_text().lines().filter_map(parse_line).collect();
        assert_eq!(
            lines,
            vec![("off".to_string(), false), ("on".to_string(), true)]
        );
    }

    #[test]
    fn a_line_in_neither_form_is_skipped_rather_than_guessed_at() {
        assert_eq!(parse_line("+yes"), Some(("yes".to_string(), true)));
        assert_eq!(parse_line("-no"), Some(("no".to_string(), false)));
        assert_eq!(parse_line("bare"), None);
        assert_eq!(parse_line("+"), None);
        assert_eq!(parse_line(""), None);
    }

    /// Turning a host off and on again must not lose where the file said it was rooted. The
    /// remembered set carries no base at all, so a merge that replaced rather than overlaid
    /// would silently re-root it at the remote's home.
    #[test]
    fn turning_one_off_and_on_keeps_the_base_the_file_gave_it() {
        let mut set = Set::new(vec![Host {
            name: "panza".to_string(),
            base: Some("~/work".to_string()),
            enabled: true,
        }]);
        set.set("panza", false, None);
        set.set("panza", true, None);
        assert_eq!(
            set.get("panza").and_then(|h| h.base.as_deref()),
            Some("~/work")
        );
    }
}
