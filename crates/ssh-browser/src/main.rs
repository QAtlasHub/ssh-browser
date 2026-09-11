//! ssh-browser: open files on an SSH host as a real browser origin.

use anyhow::{Context, Result, bail, ensure};
use ssh_browser::control::Token;
use ssh_browser::origin::{Alias, Origin, pac};

const USAGE: &str = "usage:\n  ssh-browser serve [--port N] [--suffix S] <alias>=<ssh-host>:<base> ...\n  ssh-browser pac   [--port N] [--suffix S]";

const DEFAULT_PORT: u16 = 7391;
const DEFAULT_SUFFIX: &str = "ssh-browser";

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = argv.split_first() else {
        bail!("{USAGE}");
    };

    let mut port = DEFAULT_PORT;
    let mut suffix = DEFAULT_SUFFIX.to_string();
    let mut aliases = Vec::new();

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--port" => {
                port = rest
                    .get(i + 1)
                    .context("--port needs a value")?
                    .parse()
                    .context("--port must be a number")?;
                i += 2;
            }
            "--suffix" => {
                suffix = rest.get(i + 1).context("--suffix needs a value")?.clone();
                i += 2;
            }
            spec => {
                aliases.push(parse_alias(spec)?);
                i += 1;
            }
        }
    }

    match command.as_str() {
        "pac" => {
            print!("{}", pac::script(&suffix, port)?);
            Ok(())
        }
        "serve" => {
            ensure!(
                !aliases.is_empty(),
                "give at least one <alias>=<ssh-host>:<base>\n\n{USAGE}"
            );
            // A PAC is not discoverable, so the startup banner says outright what
            // to do with it rather than leaving it to be found.
            eprintln!("listening on 127.0.0.1:{port}");
            for a in &aliases {
                eprintln!("  http://{}.{suffix}/  ->  {}:{}", a.name, a.host, a.base);
            }
            eprintln!();
            eprintln!("point the browser at the generated PAC, for example:");
            eprintln!("  chrome --proxy-pac-url=http://127.0.0.1:{port}/proxy.pac");
            eprintln!();
            eprintln!("or, without touching proxy settings: http://127.0.0.1:{port}/");
            eprintln!();

            let token = Token::generate()?;
            // Printed as well as written, because a first run has nowhere else to look.
            // To stderr so that piping the daemon's output does not carry it along.
            eprintln!("control token: {}", token.as_str());
            match token.write_to_disk() {
                Some(path) => eprintln!("  also written to {}", path.display()),
                None => eprintln!("  (could not be written to disk; copy it from above)"),
            }
            eprintln!(
                "  the extension sends it as {}",
                ssh_browser::control::TOKEN_HEADER
            );

            Origin::bind(aliases, suffix, port, token)
                .await?
                .serve()
                .await
        }
        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    }
}

/// Parse `<alias>=<ssh-host>:<absolute-base>`.
fn parse_alias(spec: &str) -> Result<Alias> {
    let (name, rest) = spec
        .split_once('=')
        .with_context(|| format!("expected <alias>=<ssh-host>:<base>, got {spec:?}"))?;
    let (host, base) = rest
        .split_once(':')
        .with_context(|| format!("expected <ssh-host>:<base> after the =, got {rest:?}"))?;

    ensure!(!name.is_empty(), "alias name is empty in {spec:?}");
    ensure!(!host.is_empty(), "ssh host is empty in {spec:?}");
    // The alias becomes a hostname label, so it has to be able to be one.
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "alias {name:?} must be lowercase letters, digits and hyphens: it becomes a hostname label"
    );
    ensure!(
        base.starts_with('/'),
        "base path must be absolute, got {base:?}"
    );

    Ok(Alias {
        name: name.to_string(),
        host: host.to_string(),
        base: base.to_string(),
    })
}
