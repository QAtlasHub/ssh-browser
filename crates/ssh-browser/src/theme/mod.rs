//! What a directory listing looks like.
//!
//! The palettes are [base16] schemes, vendored under `crates/ssh-browser/themes/`. souta
//! asked whether there was a standard for this rather than a hand-rolled set, and there is:
//! base16 is a spec with several hundred schemes behind it, every one of them sixteen hex
//! values and a name. This module is an implementation of that format.
//!
//! Which also settles the objection to the palettes it replaces. Inventing five of my own
//! meant five things nobody else had opinions about; naming them after somebody's editor
//! theme would have been a promise to keep matching a moving target in another repository.
//! Implementing a *format* is neither.
//!
//! Every rule in the listing's stylesheet is written against the custom properties built
//! here, so adding a scheme is dropping a file in — not a second copy of the layout.
//!
//! [base16]: https://github.com/tinted-theming/home/blob/main/styling.md

use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::{Result, bail};

/// The theme used when nothing says otherwise.
///
/// Following the operating system, because a page that ignores the system setting is the
/// one thing every dark-mode reader notices immediately.
pub const DEFAULT: &str = "auto";

/// The pair `auto` follows the system with: base16's own reference schemes.
///
/// The spec's defaults rather than a favourite, so the thing you get without choosing is
/// not a choice somebody made for you.
const AUTO_LIGHT: &str = "default-light";
const AUTO_DARK: &str = "default-dark";

/// The vendored schemes, compiled in.
///
/// A curated set rather than all three hundred and thirty-nine: a list you scroll past is
/// not a choice, and these are the ones somebody would recognise by name. Adding one is a
/// file and a line.
///
/// Compiled in rather than read at startup so that a daemon is one binary with no directory
/// of assets to lose, and so a missing scheme is a build error rather than a blank page.
const SCHEMES: &[(&str, &str)] = &[
    (
        "default-light",
        include_str!("../../themes/default-light.yaml"),
    ),
    (
        "default-dark",
        include_str!("../../themes/default-dark.yaml"),
    ),
    ("github", include_str!("../../themes/github.yaml")),
    ("github-dark", include_str!("../../themes/github-dark.yaml")),
    (
        "catppuccin-latte",
        include_str!("../../themes/catppuccin-latte.yaml"),
    ),
    (
        "catppuccin-mocha",
        include_str!("../../themes/catppuccin-mocha.yaml"),
    ),
    (
        "gruvbox-light-hard",
        include_str!("../../themes/gruvbox-light-hard.yaml"),
    ),
    (
        "gruvbox-dark-hard",
        include_str!("../../themes/gruvbox-dark-hard.yaml"),
    ),
    (
        "solarized-light",
        include_str!("../../themes/solarized-light.yaml"),
    ),
    (
        "solarized-dark",
        include_str!("../../themes/solarized-dark.yaml"),
    ),
    (
        "rose-pine-dawn",
        include_str!("../../themes/rose-pine-dawn.yaml"),
    ),
    ("rose-pine", include_str!("../../themes/rose-pine.yaml")),
    ("one-light", include_str!("../../themes/one-light.yaml")),
    ("onedark", include_str!("../../themes/onedark.yaml")),
    ("nord", include_str!("../../themes/nord.yaml")),
    (
        "tokyo-night-dark",
        include_str!("../../themes/tokyo-night-dark.yaml"),
    ),
    ("dracula", include_str!("../../themes/dracula.yaml")),
];

pub struct Theme {
    /// What it is called in configuration and on the wire: the scheme's filename.
    pub name: String,
    /// What it is called in the dashboard: the scheme's own `name`.
    pub label: String,
    /// `light`, `dark`, or `system` for the one that follows the reader's.
    pub variant: &'static str,
    /// The custom-property declarations, ready to go inside a `:root` block.
    ///
    /// Built once at startup. These come from this crate's own vendored files and never
    /// from anything a caller supplied, so there is nothing here to escape — and a name
    /// arriving from outside is matched against this table rather than interpolated
    /// anywhere. See [`css_for`].
    vars: String,
}

fn themes() -> &'static [Theme] {
    static PARSED: OnceLock<Vec<Theme>> = OnceLock::new();
    PARSED.get_or_init(|| {
        let mut out = vec![Theme {
            name: DEFAULT.to_string(),
            label: "Follow the system".to_string(),
            variant: "system",
            // Filled by `css_for`, which needs both halves and a media query.
            vars: String::new(),
        }];
        for (name, text) in SCHEMES {
            // A vendored file that will not parse is this repository's own mistake, not a
            // reader's, and it is caught by `every_vendored_scheme_parses` rather than by
            // somebody opening a directory and finding no colours.
            if let Some(scheme) = Scheme::parse(text) {
                let vars = scheme.vars();
                out.push(Theme {
                    name: (*name).to_string(),
                    label: scheme.label,
                    variant: if scheme.dark { "dark" } else { "light" },
                    vars,
                });
            }
        }
        out
    })
}

pub fn all() -> &'static [Theme] {
    themes()
}

pub fn exists(name: &str) -> bool {
    themes().iter().any(|t| t.name == name)
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
    let known: Vec<&str> = themes().iter().map(|t| t.name.as_str()).collect();
    bail!("no theme called {name:?}; try one of: {}", known.join(", "))
}

/// The `:root` block for a theme, including the system-following pair when it follows.
///
/// An unknown name falls back to the default rather than failing: by the time a page is
/// being rendered there is nothing useful to do with an error, and a listing with no
/// variables set is invisible text rather than merely wrong. Names are checked where they
/// are set.
pub fn css_for(name: &str) -> String {
    let found = themes().iter().find(|t| t.name == name);
    match found {
        Some(t) if t.variant != "system" => format!(":root{{{}}}", t.vars),
        // Both palettes, and the browser picks. This way round so that a browser without
        // the query still gets a complete light palette rather than no variables at all.
        _ => {
            let light = vars_named(AUTO_LIGHT);
            let dark = vars_named(AUTO_DARK);
            format!(":root{{{light}}}@media(prefers-color-scheme:dark){{:root{{{dark}}}}}")
        }
    }
}

fn vars_named(name: &str) -> &'static str {
    themes()
        .iter()
        .find(|t| t.name == name)
        .map_or("", |t| t.vars.as_str())
}

/// A parsed base16 file: the sixteen colours, and enough metadata to label it.
struct Scheme {
    label: String,
    dark: bool,
    palette: [String; 16],
}

impl Scheme {
    /// Read a base16 YAML file.
    ///
    /// Hand-written rather than through a YAML library, because the format is `key: value`
    /// and one indented block of the same, and the alternative is a parser for the whole of
    /// YAML in a daemon that reads other people's filesystems. Every vendored file is held
    /// to this by a test.
    fn parse(text: &str) -> Option<Self> {
        let mut label = None;
        let mut variant = None;
        // `None` for a slot that never appeared, which is what makes a short file fail
        // rather than render with a hole in it.
        let mut palette: [Option<String>; 16] = [const { None }; 16];

        for line in text.lines() {
            let Some((key, value)) = field(line) else {
                continue;
            };
            match key {
                "name" => label = Some(value),
                "variant" => variant = Some(value),
                _ => {
                    if let Some(slot) = base_index(key) {
                        palette[slot] = Some(value);
                    }
                }
            }
        }

        let mut colours: Vec<String> = Vec::with_capacity(16);
        for slot in palette {
            colours.push(slot?);
        }
        Some(Self {
            label: label?,
            // Anything that is not said to be light is treated as dark, which is the way
            // round that matches the schemes: a light one always says so.
            dark: variant.as_deref() != Some("light"),
            palette: colours.try_into().ok()?,
        })
    }

    /// base16's sixteen slots, as the properties the listing's rules are written against.
    ///
    /// The mapping is the spec's own meanings rather than a guess at which colour looks
    /// nice. `base00` is the background and `base05` the foreground in every scheme, light
    /// or dark, which is what lets one mapping serve both: a light scheme simply has its
    /// `base00`..`base07` running the other way.
    fn vars(&self) -> String {
        let c = |i: usize| self.palette[i].as_str();
        [
            // base00 background, base01 a shade off it, base02 the selection background.
            format!("--bg:{}", c(0x0)),
            format!("--hover:{}", c(0x1)),
            format!("--line:{}", c(0x1)),
            format!("--sel:{}", c(0x2)),
            // base03 is comments — the least contrast a reader is still meant to read.
            format!("--faint:{}", c(0x3)),
            format!("--dim:{}", c(0x4)),
            format!("--fg:{}", c(0x5)),
            // base0D is functions and headings: the scheme's own idea of "this one matters".
            format!("--accent:{}", c(0xD)),
            // The type colours. base09 is markup and constants, which is where HTML belongs;
            // base0A data; base0B strings, so media; base0D headings, so documents; base0E
            // keywords, so code.
            format!("--k-page:{}", c(0x9)),
            format!("--k-doc:{}", c(0xD)),
            format!("--k-data:{}", c(0xA)),
            format!("--k-code:{}", c(0xE)),
            format!("--k-media:{}", c(0xB)),
            format!("--k-plain:{}", c(0x3)),
            // base08 is what every scheme paints an error in, base0B what it paints a string
            // in. The dashboard had its own red and green, written as two hex values no
            // palette had a say in — which is why choosing a dark theme turned the daemon's
            // pages dark and left the dashboard white.
            format!("--bad:{}", c(0x8)),
            format!("--good:{}", c(0xB)),
        ]
        .join(";")
    }
}

/// `key: "value"` or `key: value`, with a trailing `# comment` dropped.
fn field(line: &str) -> Option<(&str, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, rest) = line.split_once(':')?;
    let rest = rest.trim();
    let value = match rest.strip_prefix('"') {
        // Quoted: everything to the closing quote, so a `#` inside it survives.
        Some(quoted) => quoted.split('"').next()?,
        // Bare: everything before a comment.
        None => rest.split('#').next()?.trim(),
    };
    (!value.is_empty()).then(|| (key.trim(), value.to_string()))
}

/// `base00`..`base0F` to `0`..`15`.
fn base_index(key: &str) -> Option<usize> {
    let digits = key.strip_prefix("base")?;
    (digits.len() == 2)
        .then(|| usize::from_str_radix(digits, 16).ok())
        .flatten()
        .filter(|slot| *slot < 16)
}

/// Where a chosen theme is remembered between runs.
///
/// Beside the token rather than in the user's `config.toml`. That file is hand-written and
/// carries their comments, and a daemon that rewrote it would eventually lose one. The
/// config file still sets the starting value; this records a later change of mind.
fn stored_path() -> Option<PathBuf> {
    Some(crate::control::state_dir()?.join("theme"))
}

/// The remembered theme, if there is one and it still exists.
///
/// A name that no longer names a theme is ignored rather than refused: it means this file
/// outlived a scheme being dropped, and refusing to start over a colour would be absurd.
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

    /// Every vendored file, through the real parser. A scheme that will not parse is
    /// dropped silently at startup by design — there is nothing useful to do about it while
    /// serving a page — so this is the only thing standing between a bad file and a theme
    /// that quietly does not exist.
    #[test]
    fn every_vendored_scheme_parses() {
        for (name, text) in SCHEMES {
            let scheme = Scheme::parse(text).unwrap_or_else(|| panic!("{name} did not parse"));
            assert!(!scheme.label.is_empty(), "{name} has no label");
            for (slot, colour) in scheme.palette.iter().enumerate() {
                assert!(
                    colour.starts_with('#') && colour.len() == 7,
                    "{name} base{slot:02X} is {colour:?}, which is not a hex colour"
                );
            }
        }
        assert_eq!(
            themes().len(),
            SCHEMES.len() + 1,
            "one of the vendored schemes was dropped, plus auto"
        );
    }

    /// The layout is written against these, so a palette missing one renders a listing with
    /// an unset colour — not a visual nit, invisible text.
    #[test]
    fn every_theme_sets_every_variable() {
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
            "--bad",
            "--good",
        ];
        for theme in all() {
            let css = css_for(&theme.name);
            for var in wanted {
                assert!(
                    css.contains(&format!("{var}:")),
                    "{} is missing {var}",
                    theme.name
                );
            }
        }
    }

    /// Both halves of the curated set are there, so choosing "light" is a real choice and
    /// not a list of dark schemes with one exception.
    #[test]
    fn the_curated_set_has_light_and_dark() {
        let light = all().iter().filter(|t| t.variant == "light").count();
        let dark = all().iter().filter(|t| t.variant == "dark").count();
        assert!(light >= 6, "only {light} light schemes");
        assert!(dark >= 6, "only {dark} dark schemes");
    }

    /// The default follows the system, and following the system means shipping both.
    #[test]
    fn the_default_carries_a_light_and_a_dark_palette() {
        let css = css_for(DEFAULT);
        assert!(css.contains("prefers-color-scheme:dark"), "{css}");
        assert!(css.contains(vars_named(AUTO_LIGHT)), "{css}");
        assert!(css.contains(vars_named(AUTO_DARK)), "{css}");
    }

    /// Choosing one means choosing it, not preferring it. A fixed theme that still flipped
    /// with the system setting would be the choice doing nothing.
    #[test]
    fn a_fixed_theme_does_not_follow_the_system() {
        let css = css_for("gruvbox-dark-hard");
        assert!(!css.contains("prefers-color-scheme"), "{css}");
        // base16's mapping, not a guess: base00 is the background in every scheme.
        assert!(css.contains("--bg:#1d2021"), "{css}");
        assert!(css.contains("--fg:#d5c4a1"), "{css}");
    }

    /// A light scheme runs base00..base07 the other way, and the same mapping has to serve
    /// it — which is the property that makes one mapping enough for both.
    #[test]
    fn a_light_scheme_maps_the_same_way_round() {
        let css = css_for("gruvbox-light-hard");
        assert!(
            css.contains("--bg:#f9f5d7"),
            "the background is base00: {css}"
        );
        assert!(
            css.contains("--fg:#504945"),
            "the foreground is base05: {css}"
        );
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
        assert!(
            said.contains("nord"),
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
        let mut names: Vec<&str> = all().iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "two themes share a name");
    }

    /// The shapes a base16 file actually comes in, including the trailing comments every
    /// scheme carries and the quoted values that may hold a `#` of their own.
    #[test]
    fn the_parser_reads_the_shapes_these_files_come_in() {
        assert_eq!(
            field(r##"  base00: "#1d2021" # ----"##),
            Some(("base00", "#1d2021".to_string()))
        );
        assert_eq!(
            field(r#"name: "Gruvbox dark, hard""#),
            Some(("name", "Gruvbox dark, hard".to_string()))
        );
        assert_eq!(field("# a whole-line comment"), None);
        assert_eq!(field(""), None);
        assert_eq!(field("palette:"), None);
    }

    #[test]
    fn base_slots_are_read_as_hex() {
        assert_eq!(base_index("base00"), Some(0));
        assert_eq!(base_index("base0F"), Some(15));
        assert_eq!(base_index("base0f"), Some(15));
        // base24 goes further; those slots are not ours to map.
        assert_eq!(base_index("base10"), None);
        assert_eq!(base_index("name"), None);
        assert_eq!(base_index("base0"), None);
    }

    /// A file that stops short renders a listing with holes in it, so it is refused whole.
    #[test]
    fn a_scheme_missing_a_colour_is_not_a_scheme() {
        let short = "system: \"base16\"\nname: \"Short\"\nvariant: \"dark\"\npalette:\n  base00: \"#000000\"\n";
        assert!(Scheme::parse(short).is_none());
    }
}
