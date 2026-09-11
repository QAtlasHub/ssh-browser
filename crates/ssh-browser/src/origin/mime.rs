//! Extension to Content-Type.
//!
//! Short on purpose, but two entries are load-bearing rather than cosmetic. A
//! browser refuses to execute an ES module served as `application/octet-stream`,
//! so getting `.mjs` and `.js` wrong makes a working page look broken in a way
//! that has nothing to do with the transport.

pub fn guess(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some((_, ext)) = name.rsplit_once('.') else {
        return "application/octet-stream";
    };
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "xml" => "application/xml",
        "csv" => "text/csv; charset=utf-8",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules_get_a_type_a_browser_will_execute() {
        assert_eq!(guess("/a/b.mjs"), "text/javascript; charset=utf-8");
        assert_eq!(guess("/a/b.js"), "text/javascript; charset=utf-8");
    }

    #[test]
    fn the_extension_comes_from_the_basename_not_the_path() {
        // A dot in a directory name must not be read as the file's extension.
        assert_eq!(guess("/a.css/b"), "application/octet-stream");
        assert_eq!(guess("/a.css/b.html"), "text/html; charset=utf-8");
    }

    #[test]
    fn unknown_and_extensionless_fall_back() {
        assert_eq!(guess("/README"), "application/octet-stream");
        assert_eq!(guess("/a.qqq"), "application/octet-stream");
    }
}
