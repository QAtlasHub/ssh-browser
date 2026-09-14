//! A configuration file, so that six hosts are not six command lines.
//!
//! Unknown keys are refused rather than ignored. A configuration file is exactly where a typo
//! is invisible: `suffixx = "dev"` that is quietly dropped leaves the daemon running on a suffix
//! nobody chose, and looking no different from one that was configured. Refusing costs one
//! confusing start and saves an hour of confusion later.
//!
//! Aliases from a file are built through [`Alias::new`], the same constructor the command line
//! uses. Two entry points and one set of rules is fine; two entry points and two copies of the
//! rules is how the looser copy becomes the one that matters.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::origin::Alias;

/// The `[server]` table. Every key is optional: a file listing only aliases is a perfectly
/// good file, and the defaults belong to the command line that owns them.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub port: Option<u16>,
    pub suffix: Option<String>,
    /// What directory listings look like. See `crate::theme`.
    ///
    /// The starting value only: a theme chosen later from the dashboard is remembered
    /// beside the token rather than written back here, because this file is hand-written
    /// and a daemon that rewrote it would eventually lose somebody's comment.
    pub theme: Option<String>,
    /// `http` or `https`.
    ///
    /// `https` terminates TLS behind a `CONNECT`, using a local authority constrained to the
    /// suffix — see `crate::tls`. It needs that authority trusted once, which `ssh-browser
    /// trust` prints the command for, so it is opt-in rather than the default.
    pub scheme: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliasEntry {
    name: String,
    host: String,
    /// Omitted means the remote's home directory.
    ///
    /// The default that makes an alias worth writing at all: a host name and nothing
    /// else. Resolved by asking the remote, in `Origin::bind`.
    #[serde(default)]
    base: Option<String>,
}

/// A host from `ssh_config` that is reachable at its URL without being opened first.
///
/// The difference from `[[alias]]` is when the connection happens. An alias is connected while
/// the daemon starts, so a host that is down stops it starting; one of these is connected the
/// first time somebody navigates to it, so naming ten costs nothing until one is used.
///
/// **Only the name is written here.** Which account, which port, which jump host — all of that
/// is already in `ssh_config`, and copying any of it into a second file would mean two answers
/// to one question and a new place for the interesting ones to sit.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEntry {
    /// A `Host` from `ssh_config`. Also the label in the URL.
    name: String,
    /// Omitted means the remote's home directory, as for an alias.
    #[serde(default)]
    base: Option<String>,
    /// Written out so a host can be turned off without deleting the line that says where it
    /// is rooted. Absent means on: a host somebody bothered to write down is one they want.
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    server: Server,
    /// `[[alias]]` in the file, because each table is one alias; `aliases` here, because this
    /// is all of them.
    #[serde(default, rename = "alias")]
    aliases: Vec<AliasEntry>,
    #[serde(default, rename = "host")]
    hosts: Vec<HostEntry>,
}

/// One `[[host]]`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reachable {
    pub name: String,
    pub base: Option<String>,
    pub enabled: bool,
}

#[derive(Debug)]
pub struct Config {
    pub server: Server,
    pub aliases: Vec<Alias>,
    pub hosts: Vec<Reachable>,
}

/// Parse the text of a configuration file.
///
/// Separate from reading one so that every rule below is testable without a filesystem.
pub fn parse(text: &str) -> Result<Config> {
    let doc: Document = toml::from_str(text).context("reading the configuration")?;

    if let Some(scheme) = doc.server.scheme.as_deref() {
        ensure!(
            scheme == "http" || scheme == "https",
            "scheme = {scheme:?} is not one this daemon serves; use \"http\" or \"https\""
        );
    }

    let mut aliases = Vec::with_capacity(doc.aliases.len());
    for entry in &doc.aliases {
        aliases.push(Alias::new(&entry.name, &entry.host, entry.base.as_deref())?);
    }

    let mut hosts = Vec::with_capacity(doc.hosts.len());
    for entry in &doc.hosts {
        // Built through the same constructor an alias uses, and then thrown away. The name has
        // to be a usable label — it becomes a hostname — and the base has to survive the same
        // checks, and there is no reason for a second copy of either rule that could drift
        // looser than this one.
        Alias::new(&entry.name, &entry.name, entry.base.as_deref())?;
        ensure!(
            !hosts.iter().any(|h: &Reachable| h.name == entry.name),
            "host {:?} is listed twice",
            entry.name
        );
        ensure!(
            !aliases.iter().any(|a| a.name() == entry.name),
            "{:?} is both an alias and a host; one of them would decide what that URL means and it is not obvious which",
            entry.name
        );
        hosts.push(Reachable {
            name: entry.name.clone(),
            base: entry.base.clone(),
            enabled: entry.enabled,
        });
    }

    Ok(Config {
        server: doc.server,
        aliases,
        hosts,
    })
}

/// Read a configuration file.
pub fn load(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse(&text).with_context(|| format!("in {}", path.display()))
}

/// Where a configuration file is looked for when none was named.
///
/// Resolved at runtime rather than compiled in. The configuration directory and not the
/// runtime one the control token uses: a token should disappear when the session does, and a
/// configuration should not, so the two resolve differently on purpose.
pub fn default_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .or_else(|| std::env::var_os("APPDATA"))
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("ssh-browser").join("config.toml"))
}

pub const DEFAULT_PORT: u16 = 7391;
pub const DEFAULT_SUFFIX: &str = "ssh-browser";

/// `http`, because `https` needs a root trusted once by hand and a default that silently
/// required that would fail for everybody who had not done it.
pub const DEFAULT_SCHEME: &str = "http";

/// What the command line said, all of it optional because anything it leaves out the file may
/// supply and anything neither supplies has a default.
#[derive(Debug, Default)]
pub struct Overrides {
    pub port: Option<u16>,
    pub suffix: Option<String>,
    pub scheme: Option<String>,
    pub aliases: Vec<Alias>,
}

/// What the daemon will actually run with.
#[derive(Debug)]
pub struct Resolved {
    pub port: u16,
    pub suffix: String,
    pub scheme: String,
    pub aliases: Vec<Alias>,
    /// Hosts reachable on demand. Carried through rather than merged with anything: there is
    /// no command-line half of this, because a host worth reaching every day is worth writing
    /// down once.
    pub hosts: Vec<Reachable>,
}

/// Fold the command line over the file.
///
/// Lives here rather than inside `main` so that it can be tested at all: the precedence is
/// three `or`s and an `extend`, any one of which could be turned around without a single test
/// noticing, and the result decides which host a URL reaches.
///
/// The command line wins, because it is what was typed for this run. Aliases are the
/// exception and are added rather than replacing: naming one host on the command line should
/// not silently drop the six in the file.
pub fn merge(cli: Overrides, file: Config) -> Result<Resolved> {
    let mut aliases = file.aliases;
    aliases.extend(cli.aliases);
    ensure_distinct(&aliases)?;

    Ok(Resolved {
        port: cli.port.or(file.server.port).unwrap_or(DEFAULT_PORT),
        suffix: cli
            .suffix
            .or(file.server.suffix)
            .unwrap_or_else(|| DEFAULT_SUFFIX.to_string()),
        scheme: cli
            .scheme
            .or(file.server.scheme)
            .unwrap_or_else(|| DEFAULT_SCHEME.to_string()),
        aliases,
        hosts: file.hosts,
    })
}

/// Refuse two aliases with the same name.
///
/// One would shadow the other in the session map, and which one survived would depend on the
/// order they happened to be added in. A URL quietly pointing at a different host than the one
/// configured is not something to settle by precedence.
pub fn ensure_distinct(aliases: &[Alias]) -> Result<()> {
    for (i, a) in aliases.iter().enumerate() {
        if let Some(other) = aliases[..i].iter().find(|b| b.name() == a.name()) {
            bail!(
                "alias {:?} is defined twice: {} and {}",
                a.name(),
                other.host(),
                a.host()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[server]
port = 7391
suffix = "ssh-browser"

[[alias]]
name = "docs"
host = "myhost"
base = "/srv/docs"

[[alias]]
name = "cluster"
host = "login-node"
base = "/home/me/public_html"
"#;

    #[test]
    fn a_full_file_parses() {
        let c = parse(FULL).expect("parses");
        assert_eq!(c.server.port, Some(7391));
        assert_eq!(c.server.suffix.as_deref(), Some("ssh-browser"));
        assert_eq!(c.aliases.len(), 2);
        assert_eq!(c.aliases[0].name(), "docs");
        assert_eq!(c.aliases[1].base(), Some("/home/me/public_html"));
    }

    #[test]
    fn a_file_of_only_aliases_is_fine() {
        let c =
            parse("[[alias]]\nname = \"docs\"\nhost = \"h\"\nbase = \"/srv\"\n").expect("parses");
        assert!(c.server.port.is_none());
        assert_eq!(c.aliases.len(), 1);
    }

    #[test]
    fn an_empty_file_is_fine() {
        assert!(parse("").expect("parses").aliases.is_empty());
    }

    /// Why `deny_unknown_fields` is on. A silently dropped key leaves the daemon running on
    /// something nobody chose, indistinguishable from something somebody did.
    #[test]
    fn a_misspelled_key_is_refused_rather_than_ignored() {
        let e = parse("[server]\nsuffixx = \"dev\"\n").expect_err("refused");
        assert!(
            format!("{e:#}").contains("suffixx"),
            "the error has to name the key: {e:#}"
        );
        assert!(
            parse("[[alias]]\nname = \"a\"\nhost = \"h\"\nbase = \"/b\"\nextra = 1\n").is_err()
        );
        assert!(parse("[serverr]\nport = 1\n").is_err());
    }

    /// Both schemes are served, and nothing else is.
    ///
    /// The third case is the one worth a test: a scheme this daemon does not speak has to be
    /// refused where it is written rather than quietly falling back, because serving http to a
    /// file that asked for something else is the one outcome that looks like success.
    #[test]
    fn the_two_schemes_are_accepted_and_a_third_is_refused() {
        assert!(parse("[server]\nscheme = \"http\"\n").is_ok());
        assert!(parse("[server]\nscheme = \"https\"\n").is_ok());
        for bad in ["HTTPS", "ftp", "wss", "", "http:"] {
            let e = parse(&format!("[server]\nscheme = \"{bad}\"\n"))
                .expect_err(&format!("{bad:?} should have been refused"));
            assert!(format!("{e:#}").contains("scheme"), "{e:#}");
        }
    }

    /// http unless something says otherwise.
    ///
    /// https needs a root trusted once by hand, so a default that silently required that would
    /// fail for everybody who had not done it — and fail at the TLS layer, where the reason is
    /// least visible.
    #[test]
    fn the_default_scheme_is_http() {
        let r = merge(Overrides::default(), parse("").expect("empty parses")).expect("merges");
        assert_eq!(r.scheme, "http");
    }

    /// And `--scheme` wins over the file, like the rest of the command line.
    #[test]
    fn the_command_line_scheme_wins() {
        let file = parse("[server]\nscheme = \"http\"\n").expect("parses");
        let cli = Overrides {
            scheme: Some("https".to_string()),
            ..Overrides::default()
        };
        assert_eq!(merge(cli, file).expect("merges").scheme, "https");
    }

    /// The command line's rules, reached through the same constructor rather than written out
    /// again here.
    #[test]
    fn an_alias_from_a_file_is_checked_like_one_from_the_command_line() {
        for bad in [
            "[[alias]]\nname = \"Docs\"\nhost = \"h\"\nbase = \"/srv\"\n",
            "[[alias]]\nname = \"a.b\"\nhost = \"h\"\nbase = \"/srv\"\n",
            "[[alias]]\nname = \"docs\"\nhost = \"h\"\nbase = \"relative\"\n",
            "[[alias]]\nname = \"docs\"\nhost = \"\"\nbase = \"/srv\"\n",
            // A leading or trailing hyphen is a label `guard::classify` refuses on every
            // request. The constructor used to accept both, so the daemon connected over ssh,
            // printed the route, listed it as a link — and then served a 403 to anyone who
            // followed it.
            "[[alias]]\nname = \"-docs\"\nhost = \"h\"\nbase = \"/srv\"\n",
            "[[alias]]\nname = \"docs-\"\nhost = \"h\"\nbase = \"/srv\"\n",
        ] {
            assert!(parse(bad).is_err(), "should have been refused:\n{bad}");
        }
    }

    #[test]
    fn a_missing_alias_field_is_refused() {
        for bad in [
            "[[alias]]\nhost = \"h\"\nbase = \"/srv\"\n",
            "[[alias]]\nname = \"docs\"\nbase = \"/srv\"\n",
        ] {
            assert!(parse(bad).is_err(), "should have been refused:\n{bad}");
        }
    }

    /// The short form, and the one worth typing: a name and a host, nothing else.
    ///
    /// `None` rather than a path, because where the home directory is lives on the remote.
    /// Filling it in here would mean this machine's home directory, which belongs to a
    /// different computer.
    #[test]
    fn an_alias_without_a_base_means_the_home_directory() {
        let c = parse("[[alias]]\nname = \"docs\"\nhost = \"h\"\n").expect("parses");
        assert_eq!(c.aliases[0].base(), None);
    }

    #[test]
    fn a_host_needs_only_a_name_and_is_on_by_default() {
        let c = parse(
            "[[host]]
name = \"login-node\"
",
        )
        .expect("parses");
        assert_eq!(c.hosts.len(), 1);
        assert_eq!(c.hosts[0].name, "login-node");
        assert_eq!(c.hosts[0].base, None);
        assert!(
            c.hosts[0].enabled,
            "a host somebody wrote down is one they want"
        );
    }

    #[test]
    fn a_host_can_be_turned_off_without_deleting_where_it_is_rooted() {
        let c = parse(
            "[[host]]
name = \"n\"
base = \"~/w\"
enabled = false
",
        )
        .expect("parses");
        assert!(!c.hosts[0].enabled);
        assert_eq!(c.hosts[0].base.as_deref(), Some("~/w"));
    }

    /// Nothing about *how* to reach a host belongs here — that is `ssh_config`'s job, and two
    /// answers to one question is how they come to disagree. An unknown key is refused rather
    /// than ignored, so writing one is a failed start and not a silently different connection.
    #[test]
    fn a_host_may_not_carry_ssh_details() {
        for line in [
            "user = \"me\"",
            "port = 22",
            "hostname = \"h\"",
            "proxyJump = \"j\"",
        ] {
            assert!(
                parse(&format!(
                    "[[host]]
name = \"n\"
{line}
"
                ))
                .is_err(),
                "{line} should have been refused"
            );
        }
    }

    /// Two rows for the same name, or a name that is also an alias, would each make one URL
    /// mean two things — and which one won would depend on the order they were read in.
    #[test]
    fn a_name_may_not_mean_two_things() {
        assert!(
            parse(
                "[[host]]
name = \"n\"
[[host]]
name = \"n\"
"
            )
            .is_err()
        );
        assert!(
            parse(
                "[[alias]]
name = \"n\"
host = \"h\"
[[host]]
name = \"n\"
"
            )
            .is_err()
        );
    }

    /// The name becomes a hostname label, so it is held to the same rule an alias name is —
    /// here, where it is written, rather than on every request after the daemon has already
    /// connected and announced the route.
    #[test]
    fn a_host_name_that_cannot_be_a_label_is_refused_where_it_is_written() {
        assert!(
            parse(
                "[[host]]
name = \"-nope\"
"
            )
            .is_err()
        );
        assert!(
            parse(
                "[[host]]
name = \"\"
"
            )
            .is_err()
        );
    }

    fn alias(name: &str, host: &str) -> Alias {
        Alias::new(name, host, Some("/srv")).expect("a valid alias")
    }

    fn file_with(server: Server, aliases: Vec<Alias>) -> Config {
        Config {
            server,
            aliases,
            hosts: Vec::new(),
        }
    }

    /// What was typed for this run wins over what was written down for every run.
    #[test]
    fn the_command_line_wins_over_the_file() {
        let file = file_with(
            Server {
                port: Some(1111),
                suffix: Some("from-file".to_string()),
                theme: None,
                scheme: None,
            },
            vec![],
        );
        let cli = Overrides {
            port: Some(2222),
            suffix: Some("from-cli".to_string()),
            scheme: None,
            aliases: vec![],
        };

        let r = merge(cli, file).expect("merges");
        assert_eq!(r.port, 2222);
        assert_eq!(r.suffix, "from-cli");
    }

    #[test]
    fn the_file_supplies_what_the_command_line_does_not() {
        let file = file_with(
            Server {
                port: Some(1111),
                suffix: Some("from-file".to_string()),
                theme: None,
                scheme: None,
            },
            vec![],
        );

        let r = merge(Overrides::default(), file).expect("merges");
        assert_eq!(r.port, 1111);
        assert_eq!(r.suffix, "from-file");
        // Neither said, so the default stands.
    }

    #[test]
    fn what_neither_supplies_falls_back() {
        let r = merge(Overrides::default(), file_with(Server::default(), vec![])).expect("merges");
        assert_eq!(r.port, DEFAULT_PORT);
        assert_eq!(r.suffix, DEFAULT_SUFFIX);
    }

    /// Added, not replaced. Naming one host on the command line must not drop the ones in the
    /// file, which is the difference between an override and an amendment.
    #[test]
    fn aliases_from_both_places_are_kept() {
        let r = merge(
            Overrides {
                aliases: vec![alias("cli", "h")],
                ..Overrides::default()
            },
            file_with(Server::default(), vec![alias("file", "h")]),
        )
        .expect("merges");

        let names: Vec<&str> = r.aliases.iter().map(Alias::name).collect();
        assert_eq!(names, ["file", "cli"]);
    }

    /// And a name in both places is a collision, because whichever won would depend on the
    /// order they happened to be added in.
    #[test]
    fn a_name_given_in_both_places_is_refused() {
        let e = merge(
            Overrides {
                aliases: vec![alias("docs", "from-cli")],
                ..Overrides::default()
            },
            file_with(Server::default(), vec![alias("docs", "from-file")]),
        )
        .expect_err("refused");
        assert!(format!("{e:#}").contains("docs"), "{e:#}");
    }

    #[test]
    fn two_aliases_with_one_name_are_refused() {
        let docs = |host: &str| Alias::new("docs", host, Some("/srv")).expect("valid");
        assert!(ensure_distinct(&[docs("a"), docs("b")]).is_err());
        let other = Alias::new("other", "b", Some("/srv")).expect("valid");
        assert!(ensure_distinct(&[docs("a"), other]).is_ok());
    }

    #[test]
    fn the_default_path_is_resolved_at_runtime() {
        // Whichever variable the platform offers, the tail is the same and nothing is
        // compiled in.
        if let Some(p) = default_path() {
            assert!(p.ends_with(Path::new("ssh-browser").join("config.toml")));
        }
    }
}
