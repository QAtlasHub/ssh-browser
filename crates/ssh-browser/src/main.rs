//! ssh-browser: open files on an SSH host as a real browser origin.

use anyhow::{Context, Result, bail, ensure};
use ssh_browser::control::Token;
use ssh_browser::origin::{Alias, Origin, pac};

const USAGE: &str = "usage:\n  ssh-browser serve [--port N] [--suffix S] [--author NAME] <alias>=<ssh-host>:<base> ...\n  ssh-browser pac   [--port N] [--suffix S]";

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
    let mut author = default_author();
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
            "--author" => {
                author = rest.get(i + 1).context("--author needs a value")?.clone();
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
            // Built before the aliases are handed over, and printed after the listener
            // exists. The old order announced "listening" first, which was a claim about
            // something that had not happened: taking the port and connecting every host
            // both happen inside `bind`, so a reader who acted on that line met a refused
            // connection, and a port already in use produced the announcement followed by
            // the error saying otherwise.
            let routes: Vec<String> = aliases
                .iter()
                .map(|a| format!("  http://{}.{suffix}/  ->  {}:{}", a.name, a.host, a.base))
                .collect();

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
            eprintln!("  annotations are written as {author}");
            eprintln!();

            // Said before the wait rather than after it, so a slow handshake looks like a
            // handshake instead of a hang.
            match routes.len() {
                1 => eprintln!("connecting over ssh..."),
                n => eprintln!("connecting {n} hosts over ssh..."),
            }
            let bound = Origin::bind(aliases, suffix.clone(), port, token, author).await?;

            // Everything from here is true by the time it is said.
            eprintln!("listening on 127.0.0.1:{port}");
            for route in &routes {
                eprintln!("{route}");
            }
            eprintln!();
            // A PAC is not discoverable, so the banner says outright what to do with it
            // rather than leaving it to be found.
            eprintln!("point the browser at the generated PAC, for example:");
            eprintln!("  chrome --proxy-pac-url=http://127.0.0.1:{port}/proxy.pac");
            eprintln!();
            eprintln!("or, without touching proxy settings: http://127.0.0.1:{port}/");

            bound.serve().await
        }
        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    }
}

/// Who annotations are written as, unless `--author` says otherwise.
///
/// The local account name, which is a guess at the remote one. The SFTP transport never
/// runs a shell, so the remote account is not something this process can ask for, and
/// inferring it from a home directory path would be a guess presented as a fact. Naming it
/// explicitly is the honest default until a listing's uid can be checked against it.
fn default_author() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
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
