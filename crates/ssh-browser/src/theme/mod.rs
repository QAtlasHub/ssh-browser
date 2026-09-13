//! What a directory listing looks like.
//!
//! A theme is a set of custom-property values and nothing else. Every rule in the listing's
//! stylesheet is written against those properties, so adding a theme is adding a palette
//! rather than a second copy of the layout — which is the point: souta asked for this to be
//! selectable 「一応スタイルはいろいろ定義する可能性を考えて」, and a scheme where a new
//! theme means new rules is one where the rules drift apart.
//!
//! The names are this project's own rather than borrowed from an editor. A palette that
//! claims to *be* somebody's theme has to keep being it, and that is a promise about a
//! moving target in somebody else's repository.

use std::path::PathBuf;

use anyhow::{Result, bail};

/// The theme used when nothing says otherwise.
///
/// Following the operating system, because a page that ignores the system setting is the
/// one thing every dark-mode reader notices immediately.
pub const DEFAULT: &str = "auto";

pub struct Theme {
    /// What it is called in configuration and on the wire.
    pub name: &'static str,
    /// What it is called in the dashboard.
    pub label: &'static str,
    /// Whether it follows the system rather than choosing for itself.
    pub follows_system: bool,
    /// Custom-property declarations, emitted into the listing's stylesheet verbatim.
    ///
    /// These are this crate's own constants and never anything a caller supplied, so there
    /// is nothing here to escape. A name arriving from outside is matched against this
    /// table rather than being interpolated anywhere — see [`css_for`].
    css: &'static str,
}

/// The variables every theme sets.
///
/// `--k-*` are the type colours the glyph column uses, and they are what makes a listing
/// readable at a glance the way an editor's file tree is: a `.toml` and a `.png` should not
/// look the same.
const LIGHT_VARS: &str = "--bg:#fff;--fg:#1f2328;--dim:#59636e;--faint:#818b98;\
--line:#d9dee3;--hover:#f3f5f7;--sel:#dbeafe;--accent:#0969da;\
--k-page:#bc4c00;--k-doc:#0969da;--k-data:#9a6700;--k-code:#8250df;--k-media:#1a7f37;\
--k-plain:#818b98";

const DARK_VARS: &str = "--bg:#0d1117;--fg:#e6edf3;--dim:#9198a1;--faint:#6e7681;\
--line:#2a313c;--hover:#161b22;--sel:#1f3358;--accent:#4493f8;\
--k-page:#ff9776;--k-doc:#6cb6ff;--k-data:#e3b341;--k-code:#d2a8ff;--k-media:#57ab5a;\
--k-plain:#6e7681";

const PAPER_VARS: &str = "--bg:#fbf7ef;--fg:#2e2a25;--dim:#6f665a;--faint:#8d8477;\
--line:#e3d9c6;--hover:#f3ecdf;--sel:#ece0c8;--accent:#a3622a;\
--k-page:#b24a1c;--k-doc:#38618c;--k-data:#8a6a1f;--k-code:#6b4a8a;--k-media:#3f7a4a;\
--k-plain:#8d8477";

const SLATE_VARS: &str = "--bg:#14181f;--fg:#d6dde8;--dim:#8a94a6;--faint:#6b7485;\
--line:#232b36;--hover:#1a202a;--sel:#243350;--accent:#7aa2f7;\
--k-page:#ff9e64;--k-doc:#7dcfff;--k-data:#e0af68;--k-code:#bb9af7;--k-media:#9ece6a;\
--k-plain:#6b7485";

const THEMES: &[Theme] = &[
    Theme {
        name: "auto",
        label: "Follow the system",
        follows_system: true,
        css: "",
    },
    Theme {
        name: "light",
        label: "Light",
        follows_system: false,
        css: LIGHT_VARS,
    },
    Theme {
        name: "dark",
        label: "Dark",
        follows_system: false,
        css: DARK_VARS,
    },
    Theme {
        name: "paper",
        label: "Paper",
        follows_system: false,
        css: PAPER_VARS,
    },
    Theme {
        name: "slate",
        label: "Slate",
        follows_system: false,
        css: SLATE_VARS,
    },
];

pub fn all() -> &'static [Theme] {
    THEMES
}

pub fn exists(name: &str) -> bool {
    THEMES.iter().any(|t| t.name == name)
}

/// Refuse a name that is not one of these, and say what the choices are.
///
/// Called where a theme is *set* rather than where a listing is rendered. A name nobody has
/// is a typo, and a typo that silently produced the default would leave somebody looking at
/// one palette and at a setting that claims another.
pub fn check(name: &str) -> Result<()> {
    if exists(name) {
        return Ok(());
    }
    let known: Vec<&str> = THEMES.iter().map(|t| t.name).collect();
    bail!("no theme called {name:?}; try one of: {}", known.join(", "))
}

/// The `:root` block for a theme, including the system-following pair when it follows.
///
/// An unknown name falls back to the default rather than failing: by the time a page is
/// being rendered there is nothing useful to do with an error, and a listing with no
/// variables set is invisible text rather than merely wrong. Names are checked where they
/// are set.
pub fn css_for(name: &str) -> String {
    let theme = THEMES
        .iter()
        .find(|t| t.name == name)
        .or_else(|| THEMES.iter().find(|t| t.name == DEFAULT));

    match theme {
        Some(t) if !t.follows_system => format!(":root{{{}}}", t.css),
        // Both palettes, and the browser picks. This way round so that a browser without
        // the query still gets a complete light palette rather than no variables at all.
        _ => format!(
            ":root{{{LIGHT_VARS}}}@media(prefers-color-scheme:dark){{:root{{{DARK_VARS}}}}}"
        ),
    }
}

/// Where a chosen theme is remembered between runs.
///
/// Beside the token rather than in the user's `config.toml`. That file is hand-written and
/// carries their comments, and a daemon that rewrites it would eventually lose one. The
/// config file still sets the starting value; this records a later change of mind.
fn stored_path() -> Option<PathBuf> {
    Some(crate::control::state_dir()?.join("theme"))
}

/// The remembered theme, if there is one and it still exists.
///
/// A name that no longer names a theme is ignored rather than refused: it means this file
/// outlived a rename, and refusing to start over a colour would be absurd.
pub fn remembered() -> Option<String> {
    let name = std::fs::read_to_string(stored_path()?).ok()?;
    let name = name.trim().to_string();
    exists(&name).then_some(name)
}

/// Remember a theme, and say where it went.
pub fn remember(name: &str) -> Result<PathBuf> {
    check(name)?;
    let path = match stored_path() {
        Some(path) => path,
        None => bail!("no directory to remember a theme in"),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, format!("{name}\n"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_theme_sets_every_variable() {
        // The layout is written against these, so a palette missing one renders a listing
        // with an unset colour — which is not a visual nit, it is invisible text.
        let wanted = [
            "--bg",
            "--fg",
            "--dim",
            "--faint",
            "--line",
            "--hover",
            "--sel",
            "--accent",
            "--k-page",
            "--k-doc",
            "--k-data",
            "--k-code",
            "--k-media",
            "--k-plain",
        ];
        for theme in all().iter().filter(|t| !t.follows_system) {
            for var in wanted {
                assert!(
                    theme.css.contains(&format!("{var}:")),
                    "{} is missing {var}",
                    theme.name
                );
            }
        }
    }

    /// The default follows the system, and following the system means shipping both.
    #[test]
    fn the_default_carries_a_light_and_a_dark_palette() {
        let css = css_for(DEFAULT);
        assert!(css.contains("prefers-color-scheme:dark"), "{css}");
        assert!(css.contains(LIGHT_VARS), "{css}");
        assert!(css.contains(DARK_VARS), "{css}");
    }

    /// Choosing one means choosing it, not preferring it. A fixed theme that still flipped
    /// with the system setting would be the choice doing nothing.
    #[test]
    fn a_fixed_theme_does_not_follow_the_system() {
        let css = css_for("paper");
        assert!(!css.contains("prefers-color-scheme"), "{css}");
        assert!(css.contains(PAPER_VARS), "{css}");
    }

    #[test]
    fn an_unknown_theme_renders_as_the_default_rather_than_as_nothing() {
        assert_eq!(css_for("no-such-theme"), css_for(DEFAULT));
    }

    /// But it is refused where it is *set*, which is the place that can still say so.
    #[test]
    fn an_unknown_theme_is_refused_where_it_is_configured() {
        let e = check("no-such-theme").expect_err("should be refused");
        let said = format!("{e}");
        assert!(said.contains("no-such-theme"), "{said}");
        // The choices, so the reader does not have to go and find them.
        assert!(
            said.contains("slate"),
            "the error should list the themes: {said}"
        );
    }

    #[test]
    fn the_default_is_a_theme_that_exists() {
        assert!(exists(DEFAULT));
        check(DEFAULT).expect("the default must be valid");
    }

    #[test]
    fn theme_names_are_unique() {
        let mut names: Vec<&str> = all().iter().map(|t| t.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "two themes share a name");
    }
}
