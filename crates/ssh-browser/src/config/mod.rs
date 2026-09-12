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
    pub author: Option<String>,
    /// Accepted so that asking for `https` is refused rather than ignored.
    ///
    /// The https mode is designed and not built. Of the three things that could happen to a
    /// file asking for it, serving http anyway is the worst, because it looks like it worked.
    pub scheme: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliasEntry {
    name: String,
    host: String,
    base: String,
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
}

#[derive(Debug)]
pub struct Config {
    pub server: Server,
    pub aliases: Vec<Alias>,
}

/// Parse the text of a configuration file.
///
/// Separate from reading one so that every rule below is testable without a filesystem.
pub fn parse(text: &str) -> Result<Config> {
    let doc: Document = toml::from_str(text).context("reading the configuration")?;

    if let Some(scheme) = doc.server.scheme.as_deref() {
        ensure!(
            scheme == "http",
            "scheme = {scheme:?} is not supported yet; only \"http\" is. https needs a CA constrained to the suffix, which is designed but not built"
        );
    }

    let mut aliases = Vec::with_capacity(doc.aliases.len());
    for entry in &doc.aliases {
        aliases.push(Alias::new(&entry.name, &entry.host, &entry.base)?);
    }
    Ok(Config {
        server: doc.server,
        aliases,
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
author = "souta"

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
        assert_eq!(c.server.author.as_deref(), Some("souta"));
        assert_eq!(c.aliases.len(), 2);
        assert_eq!(c.aliases[0].name(), "docs");
        assert_eq!(c.aliases[1].base(), "/home/me/public_html");
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

    /// Designed and not built. Serving http to a file that asked for https is the one outcome
    /// that looks like success.
    #[test]
    fn asking_for_https_is_refused_while_it_does_not_exist() {
        let e = parse("[server]\nscheme = \"https\"\n").expect_err("refused");
        assert!(format!("{e:#}").contains("https"), "{e:#}");
        assert!(parse("[server]\nscheme = \"http\"\n").is_ok());
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
        ] {
            assert!(parse(bad).is_err(), "should have been refused:\n{bad}");
        }
    }

    #[test]
    fn a_missing_alias_field_is_refused() {
        assert!(parse("[[alias]]\nname = \"docs\"\nhost = \"h\"\n").is_err());
    }

    #[test]
    fn two_aliases_with_one_name_are_refused() {
        let docs = |host: &str| Alias::new("docs", host, "/srv").expect("valid");
        assert!(ensure_distinct(&[docs("a"), docs("b")]).is_err());
        let other = Alias::new("other", "b", "/srv").expect("valid");
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
