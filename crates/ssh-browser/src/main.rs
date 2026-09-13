//! ssh-browser: open files on an SSH host as a real browser origin.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ssh_browser::config;
use ssh_browser::control::{self, Token};
use ssh_browser::origin::{Alias, Origin, pac};
use ssh_browser::ssh_config;
use ssh_browser::theme;

const USAGE: &str = "usage:\n  ssh-browser serve [--config FILE] [--port N] [--suffix S] [--author NAME] [--new-token] [<alias>=<ssh-host>[:<base>] ...]\n  ssh-browser pac   [--config FILE] [--port N] [--suffix S]
  ssh-browser hosts\n\nWith no --config, a file at <config dir>/ssh-browser/config.toml is used if it exists:\n\n  [server]\n  port = 7391\n  suffix = \"ssh-browser\"\n\n  [[alias]]\n  name = \"docs\"\n  host = \"myhost\"\n  base = \"~/docs\"   # or an absolute path; omit for the home directory itself";

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = argv.split_first() else {
        bail!("{USAGE}");
    };

    let mut named_config: Option<PathBuf> = None;
    let mut cli = config::Overrides::default();
    let mut new_token = false;

    // Driven by an iterator rather than an index, so the number of tokens consumed is the
    // number actually taken. With a hand-kept counter, an arm that forgets its step silently
    // reparses its own value as the next argument.
    let mut args = rest.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                named_config = Some(PathBuf::from(args.next().context("--config needs a path")?));
            }
            "--port" => {
                cli.port = Some(
                    args.next()
                        .context("--port needs a value")?
                        .parse()
                        .context("--port must be a number")?,
                );
            }
            "--suffix" => {
                cli.suffix = Some(args.next().context("--suffix needs a value")?.clone());
            }
            "--author" => {
                cli.author = Some(args.next().context("--author needs a value")?.clone());
            }
            // A flag rather than a value, so it consumes nothing: rotating is a thing you
            // do, not a thing you configure.
            "--new-token" => new_token = true,
            spec => cli.aliases.push(parse_alias(spec)?),
        }
    }

    // A named file must exist. The default one need not, because not having one is the
    // ordinary case; failing on a path the operator typed and silently skipping one they did
    // not are both the right answer to their own question.
    let file = match named_config {
        Some(path) => Some(config::load(&path)?),
        None => match config::default_path().filter(|p| p.exists()) {
            Some(path) => Some(config::load(&path)?),
            None => None,
        },
    };
    let from_file = file.unwrap_or(config::Config {
        server: config::Server::default(),
        aliases: Vec::new(),
    });

    // Read before `merge` consumes the file, because the theme is not an alias or a port
    // and has no command-line half to be merged with.
    let from_file_theme = from_file.server.theme.clone();

    let config::Resolved {
        port,
        suffix,
        author,
        aliases,
    } = config::merge(cli, from_file, default_author())?;

    match command.as_str() {
        // Prints what the extension's host list will show, so a host that does not
        // appear there can be chased without a browser in the loop.
        "hosts" => {
            let found = ssh_config::read()?;
            if found.hosts.is_empty() && found.unusable.is_empty() {
                match ssh_config::default_path() {
                    Some(path) => eprintln!("no hosts in {}", path.display()),
                    None => eprintln!("no home directory, so no ssh_config to read"),
                }
            }
            for host in &found.hosts {
                // Resolved by asking ssh, so what is printed is what the transport will
                // actually do rather than what a second parse of the file concluded.
                let s = ssh_config::describe(&host.host).await?;
                let mut parts = Vec::new();
                if let Some(user) = &s.user {
                    parts.push(format!("user {user}"));
                }
                if let Some(hostname) = &s.hostname {
                    parts.push(format!("hostname {hostname}"));
                }
                if let Some(port) = s.port {
                    parts.push(format!("port {port}"));
                }
                if let Some(jump) = &s.proxy_jump {
                    parts.push(format!("via {jump}"));
                }
                println!("{:<16} {}", host.alias, parts.join("  "));
            }
            for skipped in &found.unusable {
                eprintln!("skipped {}: {}", skipped.host, skipped.why);
            }
            Ok(())
        }
        "pac" => {
            print!("{}", pac::script(&suffix, port)?);
            Ok(())
        }
        "serve" => {
            let (token, source) = Token::load_or_generate(new_token)?;
            // Printed as well as written, because a first run has nowhere else to look.
            // To stderr so that piping the daemon's output does not carry it along.
            eprintln!("control token: {}", token.as_str());
            // Which of the two it is, said outright. Somebody who has already pasted this
            // into a browser needs to know whether they must do it again, and comparing
            // sixty-four hex characters by eye is not a way to find out.
            match source {
                control::Source::Reused(path) => eprintln!(
                    "  unchanged since last time, from {} — a browser holding it is still connected",
                    path.display()
                ),
                control::Source::Fresh(Some(path)) => eprintln!(
                    "  new, and written to {} — paste it into the extension once",
                    path.display()
                ),
                control::Source::Fresh(None) => {
                    eprintln!("  new, and could not be written to disk; copy it from above");
                }
            }
            eprintln!(
                "  the extension sends it as {}",
                ssh_browser::control::TOKEN_HEADER
            );
            eprintln!("  annotations are written as {author}");
            eprintln!();

            // Said before the wait rather than after it, so a slow handshake looks like a
            // handshake instead of a hang. It names the port as well as the hosts because
            // `bind` does both and either can fail: announcing only the ssh half put a
            // "connecting over ssh" line directly above an error about the port.
            match aliases.len() {
                0 => eprintln!("taking 127.0.0.1:{port}..."),
                1 => eprintln!("taking 127.0.0.1:{port} and connecting over ssh..."),
                n => eprintln!("taking 127.0.0.1:{port} and connecting {n} hosts over ssh..."),
            }
            // Precedence: a theme chosen from the dashboard, then the config file, then the
            // default. The remembered one wins because it is the later decision -- somebody
            // who picked a theme last week did so after writing the file.
            let theme = theme::remembered()
                .or_else(|| from_file_theme.clone())
                .unwrap_or_else(|| theme::DEFAULT.to_string());
            let bound = Origin::bind(aliases, suffix.clone(), port, token, author, theme).await?;

            // Everything from here is true by the time it is said. The routes come from
            // the bound origin rather than from the aliases, because an alias rooted at
            // the home directory does not know where it points until the remote has been
            // asked, and announcing it as "home" would leave the reader to find out which
            // directory that was.
            eprintln!("listening on 127.0.0.1:{port}");
            for route in bound.routes() {
                eprintln!("{route}");
            }
            // Starting with none is the ordinary case now: the extension opens a host from
            // your ssh_config when you pick one. Said outright, because a daemon that
            // listed nothing used to mean a misconfiguration.
            if bound.routes().is_empty() {
                eprintln!("  no aliases open yet — pick a host in the extension, or see");
                eprintln!("  `ssh-browser hosts` for what your ssh_config can reach");
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
/// explicitly with `--author` is the honest alternative.
///
/// The guess does not go unchecked: what a log claims is compared against the owner a
/// listing reports, and a mismatch is shown beside the note. See `annot::Attribution`. That
/// comparison uses the owner's *name* out of the listing's `longname`, not the numeric uid,
/// which cannot answer the question at all.
fn default_author() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Parse `<alias>=<ssh-host>[:<absolute-base>]`.
///
/// Without the base it means the remote's home directory, which is the short form worth
/// typing and the one the extension generates.
///
/// Splitting is this function's job; judging the parts is `Alias::new`'s, which is also what
/// the configuration file goes through. The rules used to live here, where a second entry
/// point could not reach them.
fn parse_alias(spec: &str) -> Result<Alias> {
    let (name, rest) = spec
        .split_once('=')
        .with_context(|| format!("expected <alias>=<ssh-host>[:<base>], got {spec:?}"))?;
    let (host, base) = match rest.split_once(':') {
        Some((host, base)) => (host, Some(base)),
        None => (rest, None),
    };
    Alias::new(name, host, base).with_context(|| format!("in {spec:?}"))
}
