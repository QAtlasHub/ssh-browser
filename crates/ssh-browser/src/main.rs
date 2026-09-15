//! ssh-browser: open files on an SSH host as a real browser origin.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ssh_browser::autostart;
use ssh_browser::config;
use ssh_browser::control::{self, Token};
use ssh_browser::origin::{Alias, Origin, pac};
use ssh_browser::reachable;
use ssh_browser::ssh_config;
use ssh_browser::theme;
use ssh_browser::tls;

const USAGE: &str = "usage:\n  ssh-browser serve [--config FILE] [--port N] [--suffix S] [--scheme http|https] [--new-token] [<alias>=<ssh-host>[:<base>] ...]\n  ssh-browser pac   [--config FILE] [--port N] [--suffix S]
  ssh-browser trust [--config FILE] [--suffix S]\n  ssh-browser autostart [--off]\n  ssh-browser hosts\n\nWith no --config, a file at <config dir>/ssh-browser/config.toml is used if it exists:\n\n  [server]\n  port = 7391\n  suffix = \"ssh-browser\"\n  scheme = \"http\"   # https terminates TLS behind CONNECT; see `ssh-browser trust`\n\n  [[alias]]\n  name = \"docs\"\n  host = \"myhost\"\n  base = \"~/docs\"   # or an absolute path; omit for the home directory itself";

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = argv.split_first() else {
        bail!("{USAGE}");
    };

    let mut named_config: Option<PathBuf> = None;
    let mut cli = config::Overrides::default();
    let mut new_token = false;
    let mut off = false;

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
            "--scheme" => {
                cli.scheme = Some(args.next().context("--scheme needs a value")?.clone());
            }
            // A flag rather than a value, so it consumes nothing: rotating is a thing you
            // do, not a thing you configure.
            "--new-token" => new_token = true,
            "--off" => off = true,
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
        hosts: Vec::new(),
    });

    // Read before `merge` consumes the file, because the theme is not an alias or a port
    // and has no command-line half to be merged with.
    let from_file_theme = from_file.server.theme.clone();

    let config::Resolved {
        port,
        suffix,
        scheme,
        aliases,
        hosts,
    } = config::merge(cli, from_file)?;

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
        // Prints and stops. Installing a root into a trust store changes how the whole machine
        // treats the internet and is not undone by uninstalling this binary, so the command is
        // the reader's to run, with it in front of them.
        //
        // Creating the authority is this command's job as well as `serve`'s, so that trusting it
        // can be done before the first https run rather than only after one has failed.
        "trust" => {
            let authority = tls::load_or_create(&suffix)?;
            let Some(path) = tls::certificate_path() else {
                bail!("no state directory to keep a local certificate authority in");
            };
            println!("{}", tls::trust_instructions(&suffix, &path));
            // What it permits, read back out of the certificate this command just wrote rather
            // than restated from the code that wrote it. Somebody deciding whether to trust a
            // root should be able to see the limit, and "take our word for it" is not that.
            match tls::limits_of(authority.certificate_pem()) {
                Ok(limits) => {
                    println!("What it is allowed to vouch for, read out of that file:");
                    println!("  names under:        {}", limits.permitted.join(", "));
                    println!(
                        "  marked critical:    {}  (so a browser cannot skip the limit)",
                        limits.constraints_critical
                    );
                    println!(
                        "  can sign a sub-CA:  {}",
                        match limits.path_len {
                            Some(0) => "no".to_string(),
                            other => format!("{other:?}"),
                        }
                    );
                }
                // Not fatal: the instructions above are the point, and this is the reassurance.
                // Refusing to print them because the extra could not be read would be backwards.
                Err(e) => println!("  (could not read the certificate back: {e:#})"),
            }
            Ok(())
        }
        // Does it, rather than printing what to do -- the opposite of `trust` above, and the
        // difference is consent. Trusting a root changes what the whole machine believes;
        // starting a program of your own at login is the thing that was asked for, and handing
        // back a command to paste would be the same failure more politely.
        "autostart" => {
            let kind = autostart::Kind::here();
            let Some(home) = autostart::home() else {
                bail!("no home directory, so nowhere to put a login entry");
            };
            let Some(state) = control::state_dir() else {
                bail!("no state directory to keep a login entry in");
            };

            let plan = if off {
                autostart::remove_plan(kind, &home, &state)
            } else {
                // Its own path, resolved now. A login session's PATH is not a shell's, and an
                // entry that starts whatever `ssh-browser` it can find may find none.
                let exe = std::env::current_exe().context("finding this executable")?;
                autostart::install_plan(kind, &exe, &home, &state)
            };
            autostart::apply(&plan)?;
            println!();
            println!("{}", plan.note);
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
            // Over the file, the same way the theme is: the file sets the starting value and
            // the dashboard records a later change of mind.
            let reachable = reachable::Set::new(
                hosts
                    .into_iter()
                    .map(|h| reachable::Host {
                        name: h.name,
                        base: h.base,
                        enabled: h.enabled,
                    })
                    .collect(),
            );
            let (bound, startup) = Origin::bind(
                aliases,
                reachable,
                suffix.clone(),
                scheme.clone(),
                port,
                token,
                theme,
            )
            .await?;

            // Everything from here is true by the time it is said. The routes come from
            // the bound origin rather than from the aliases, because an alias rooted at
            // the home directory does not know where it points until the remote has been
            // asked, and announcing it as "home" would leave the reader to find out which
            // directory that was.
            eprintln!("listening on 127.0.0.1:{port}");
            for route in startup.routes() {
                eprintln!("{route}");
            }
            // Starting with none is the ordinary case now: the extension opens a host from
            // your ssh_config when you pick one. Said outright, because a daemon that
            // listed nothing used to mean a misconfiguration.
            if startup.routes().is_empty() {
                eprintln!("  no aliases open yet — pick a host in the extension, or see");
                eprintln!("  `ssh-browser hosts` for what your ssh_config can reach");
            }
            // After the routes, so what is working is read first. An enabled host that did not
            // answer is not a reason to refuse to start — a laptop on the wrong network has
            // half of them unreachable — but it is a reason to say so, because the alternative
            // is a URL that quietly 404s and no hint as to why.
            if !startup.refused().is_empty() {
                eprintln!();
                for line in startup.refused() {
                    eprintln!("{line}");
                }
            }
            // Before the PAC advice rather than after, because it is the step that decides
            // whether following the PAC advice works at all. A first run that printed
            // `https://...` and nothing about the certificate left the reader at
            // `ERR_CERT_AUTHORITY_INVALID` with nothing to go on — measured by doing exactly
            // that on a machine which had never run this.
            if let Some(advice) = startup.trust() {
                eprintln!();
                eprintln!("{advice}");
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
    Alias::new(name, host, base)
        .map(Alias::for_this_run)
        .with_context(|| format!("in {spec:?}"))
}
