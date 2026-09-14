//! What an HTML document is about to ask for.
//!
//! This exists because of a limit in the browser, not in the remote. A page with forty
//! subresources is not forty requests made at once: HTTP/1.1 allows six connections per
//! origin, so it is seven waves, each discovered only once the previous one came back. Seven
//! waves is seven remote round trips, and the count grows with the number of subresources —
//! which is exactly what invariant 1 says must not happen.
//!
//! Reading the page's own references first collapses that to one batch. The waves then arrive
//! to find everything already held.
//!
//! The scanner is a heuristic and does not need to be better than one, because **it can only
//! affect speed, never correctness**. Every subresource is still served by a real request
//! through the real guards: a reference missed here is fetched normally, and a reference
//! invented here is a read that fails and is dropped. Nothing it does can make a page wrong.
//! That is what makes hand-scanning acceptable here when it would not be if the scan decided
//! what a reader is allowed to see.

/// How many references to take from one document.
///
/// A cap, because the scan happens before the page is answered: a document listing a thousand
/// lazy-loaded images would otherwise spend the reader's time fetching what they may never
/// scroll to.
pub const MAX_SUBRESOURCES: usize = 64;

/// The `rel` values that mean the browser will actually fetch the `href`.
///
/// Checked rather than assumed, so `rel="alternate"` pointing at a large download does not
/// get read just for sitting in a `<link>`.
const FETCHED_RELS: [&str; 5] = ["stylesheet", "icon", "preload", "modulepreload", "prefetch"];

/// Collect the subresources an HTML document refers to, in document order, without repeats.
pub fn scan(html: &[u8], max: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;

    while i < html.len() && out.len() < max {
        if html[i] != b'<' {
            i += 1;
            continue;
        }
        // A comment may contain anything at all, including something shaped like a tag.
        if html[i..].starts_with(b"<!--") {
            i = match find(html, i + 4, b"-->") {
                Some(at) => at + 3,
                None => break,
            };
            continue;
        }

        let (name, after_name) = tag_name(html, i + 1);
        if name.is_empty() {
            i += 1;
            continue;
        }
        let (attrs, after_tag) = attributes(html, after_name);

        match name.as_str() {
            "link" => {
                // A `rel` value is case-insensitive in HTML, so it is folded before being
                // compared and not only the attribute's name.
                let fetched = value(&attrs, "rel").is_some_and(|rel| {
                    rel.split_whitespace()
                        .any(|r| FETCHED_RELS.contains(&r.to_ascii_lowercase().as_str()))
                });
                if fetched {
                    push(&mut out, value(&attrs, "href"));
                }
            }
            "script" | "img" | "source" | "audio" | "video" | "iframe" | "embed" => {
                push(&mut out, value(&attrs, "src"));
            }
            _ => {}
        }

        // The body of a script or a style is not markup. A `<` inside a JavaScript string
        // would otherwise read as the start of a tag and derail everything after it.
        i = match name.as_str() {
            "script" | "style" => {
                find_close(html, after_tag, name.as_bytes()).unwrap_or(html.len())
            }
            _ => after_tag,
        };
    }

    out
}

fn push(out: &mut Vec<String>, raw: Option<&str>) {
    if let Some(url) = raw.and_then(usable)
        && !out.contains(&url)
    {
        out.push(url);
    }
}

/// Keep only references this origin could serve, stripped of what the remote never sees.
fn usable(raw: &str) -> Option<String> {
    let cut = raw.find(['?', '#']).unwrap_or(raw.len());
    let url = raw[..cut].trim();
    if url.is_empty() {
        return None;
    }
    // Protocol-relative, so somewhere else by definition.
    if url.starts_with("//") {
        return None;
    }
    // A scheme is somewhere else too, `data:` and `mailto:` included. The colon has to come
    // before any slash to be a scheme, or a filename like `t:0.5.png` would read as one.
    if let Some(colon) = url.find(':')
        && !url[..colon].contains('/')
    {
        return None;
    }
    Some(url.to_string())
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= haystack.len() || needle.len() > haystack.len() - from {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|at| from + at)
}

/// Where `</name` starts, matched without regard to case.
fn find_close(html: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut i = from;
    while i + 2 + name.len() <= html.len() {
        if html[i] == b'<'
            && html[i + 1] == b'/'
            && html[i + 2..i + 2 + name.len()].eq_ignore_ascii_case(name)
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Past any run of whitespace.
fn skip_space(html: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < html.len() && html[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Read a tag name, lowercased, and say where it ended.
fn tag_name(html: &[u8], from: usize) -> (String, usize) {
    let mut end = from;
    while end < html.len() && html[end].is_ascii_alphanumeric() {
        end += 1;
    }
    let name = String::from_utf8_lossy(&html[from..end]).to_ascii_lowercase();
    (name, end)
}

/// Read a tag's attributes up to its `>`, and say where the tag ended.
fn attributes(html: &[u8], from: usize) -> (Vec<(String, String)>, usize) {
    let mut attrs = Vec::new();
    let mut i = from;

    while i < html.len() {
        while i < html.len() && (html[i].is_ascii_whitespace() || html[i] == b'/') {
            i += 1;
        }
        if i >= html.len() || html[i] == b'>' {
            break;
        }

        let start = i;
        while i < html.len() && !html[i].is_ascii_whitespace() && html[i] != b'=' && html[i] != b'>'
        {
            i += 1;
        }
        let name = String::from_utf8_lossy(&html[start..i]).to_ascii_lowercase();

        i = skip_space(html, i);
        if i >= html.len() || html[i] != b'=' {
            // A bare attribute such as `defer`, which carries no value.
            attrs.push((name, String::new()));
            continue;
        }
        i += 1;
        i = skip_space(html, i);
        if i >= html.len() {
            break;
        }

        let (raw, next) = match html[i] {
            q @ (b'"' | b'\'') => {
                let start = i + 1;
                let end = find(html, start, &[q]).unwrap_or(html.len());
                (&html[start..end], (end + 1).min(html.len()))
            }
            _ => {
                let start = i;
                let mut end = i;
                while end < html.len() && !html[end].is_ascii_whitespace() && html[end] != b'>' {
                    end += 1;
                }
                (&html[start..end], end)
            }
        };
        attrs.push((name, String::from_utf8_lossy(raw).into_owned()));
        i = next;
    }

    (attrs, (i + 1).min(html.len()))
}

fn value<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANY: usize = 1000;

    #[test]
    fn finds_the_three_references_a_generated_page_actually_has() {
        let html = br#"<!doctype html><html><head>
            <link rel="stylesheet" href="style.css">
            <script src="app.js" defer></script>
            </head><body><img src="plot.png" alt="a plot"></body></html>"#;
        assert_eq!(scan(html, MANY), ["style.css", "app.js", "plot.png"]);
    }

    #[test]
    fn reads_single_quoted_and_unquoted_values() {
        let html = br#"<img src='a.png'><img src=b.png><img src = "c.png">"#;
        assert_eq!(scan(html, MANY), ["a.png", "b.png", "c.png"]);
    }

    #[test]
    fn tag_and_attribute_names_are_matched_regardless_of_case() {
        let html = br#"<LINK REL="Stylesheet" HREF="a.css"><IMG SRC="b.png">"#;
        assert_eq!(scan(html, MANY), ["a.css", "b.png"]);
    }

    /// A `<link>` the browser would not fetch must not be fetched here either, or a
    /// `rel="alternate"` pointing at a large download becomes part of loading the page.
    #[test]
    fn a_link_the_browser_would_not_fetch_is_left_alone() {
        let html = br#"<link rel="stylesheet" href="yes.css">
            <link rel="alternate" href="no.pdf">
            <link rel="canonical" href="no.html">
            <link href="no-rel.css">
            <link rel="icon" href="yes.ico">
            <link rel="preload modulepreload" href="yes.mjs">"#;
        assert_eq!(scan(html, MANY), ["yes.css", "yes.ico", "yes.mjs"]);
    }

    /// An `<a href>` is a page the reader has not asked for. Following those would turn
    /// opening one document into crawling the whole tree.
    #[test]
    fn ordinary_links_are_not_subresources() {
        let html = br#"<a href="other.html">other</a><form action="post.cgi"></form>"#;
        assert!(scan(html, MANY).is_empty());
    }

    #[test]
    fn references_to_somewhere_else_are_skipped() {
        // Doubled delimiter: `src="#"` would otherwise close a `br#"..."#` literal.
        let html = br##"<img src="https://example.com/a.png">
            <img src="//example.com/b.png">
            <img src="data:image/gif;base64,R0lGOD">
            <script src="http://example.com/c.js"></script>
            <img src="">
            <img src="#">"##;
        assert!(scan(html, MANY).is_empty());
    }

    /// The remote is asked for a path, and neither the query nor the fragment is part of one.
    #[test]
    fn a_query_or_fragment_is_cut_off() {
        let html = br#"<link rel="stylesheet" href="style.css?v=3">
            <img src="sprite.svg#icon">"#;
        assert_eq!(scan(html, MANY), ["style.css", "sprite.svg"]);
    }

    /// A path containing a colon is still a path. Reading it as a scheme would silently stop
    /// prefetching for anybody whose filenames contain one, which on a sweep of parameters is
    /// most of them.
    #[test]
    fn a_colon_after_a_slash_is_not_a_scheme() {
        let html = br#"<img src="plots/t:0.5.png">"#;
        assert_eq!(scan(html, MANY), ["plots/t:0.5.png"]);
    }

    /// The failure this guards against: a `<` inside JavaScript read as the start of a tag
    /// derails the scan from there on, so everything after the script is silently lost.
    #[test]
    fn a_script_body_is_not_read_as_markup() {
        let html = br#"<script src="a.js">if (x<y) { var s = "<img src=fake.png>"; }</script>
            <img src="real.png">"#;
        assert_eq!(scan(html, MANY), ["a.js", "real.png"]);
    }

    #[test]
    fn a_style_body_is_not_read_as_markup() {
        let html = br#"<style>a::before { content: "<img src=fake.png>"; }</style>
            <img src="real.png">"#;
        assert_eq!(scan(html, MANY), ["real.png"]);
    }

    #[test]
    fn a_comment_cannot_smuggle_a_reference() {
        let html = br#"<!-- <img src="commented.png"> --><img src="real.png">"#;
        assert_eq!(scan(html, MANY), ["real.png"]);
    }

    #[test]
    fn the_same_reference_is_only_returned_once() {
        let html = br#"<img src="a.png"><img src="a.png"><img src="a.png">"#;
        assert_eq!(scan(html, MANY), ["a.png"]);
    }

    #[test]
    fn the_cap_is_honoured() {
        let html: Vec<u8> = (0..100)
            .map(|i| format!("<img src=\"{i}.png\">"))
            .collect::<String>()
            .into_bytes();
        assert_eq!(scan(&html, 10).len(), 10);
        assert_eq!(scan(&html, MAX_SUBRESOURCES).len(), MAX_SUBRESOURCES);
    }

    /// Truncated markup is what a partial write or a template error produces, and the remote
    /// chooses this input. The scan has to stop rather than run off the end of the buffer.
    #[test]
    fn truncated_markup_does_not_panic() {
        for html in [
            &b"<img src=\"a.png"[..],
            b"<img src=",
            b"<img",
            b"<",
            b"<!--",
            b"<!-- <img src=\"a.png\">",
            b"<script src=\"a.js\">unclosed",
            b"<link rel=",
            b"<img src='",
        ] {
            let _ = scan(html, MANY);
        }
    }

    #[test]
    fn an_empty_document_yields_nothing() {
        assert!(scan(b"", MANY).is_empty());
        assert!(scan(b"no markup at all", MANY).is_empty());
    }
}
