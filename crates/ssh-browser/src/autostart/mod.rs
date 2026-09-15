//! Start the daemon when you log in, so nobody has to remember to.
//!
//! A reader who must run `ssh-browser serve` before their bookmarks resolve does not have a
//! product, they have a program they run. The daemon is not a thing anyone wants to think
//! about — it is what makes a URL work — so it should already be there.
//!
//! Unlike [`crate::tls`], which prints a command and executes nothing, this does the thing.
//! The difference is about consent rather than effort: trusting a certificate authority changes
//! what the whole machine believes, so it is a decision to make with your own hands. Starting a
//! program of your own at login is what was asked for, and printing a command to copy would be
//! the same failure in a politer form.
//!
//! The three platforms are a parameter rather than a `cfg!`, for the reason written out in
//! `tls::Store`: a platform-specific string only its own platform can run is a string nobody
//! tests. Here the plan is worked out as data, checked on any machine, and only [`apply`]
//! touches anything.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// How a platform starts something at login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Task Scheduler, a task for this account.
    Windows,
    /// A launchd agent in the user's own `LaunchAgents`.
    MacOs,
    /// A systemd user unit.
    Systemd,
}

impl Kind {
    /// The one this is running on.
    pub fn here() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Systemd
        }
    }
}

/// Everything a platform needs done, worked out without doing any of it.
///
/// Files first and commands second, always: each of these registers a path that has to exist
/// by the time the command referring to it runs.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub files: Vec<(PathBuf, String)>,
    pub commands: Vec<Vec<String>>,
    /// Paths to delete, after the commands. Removal fills this; installing leaves it empty.
    pub remove: Vec<PathBuf>,
    /// What to tell the reader, including how to undo it.
    pub note: String,
}

/// The reverse-DNS label launchd wants, and the name the unit goes by elsewhere.
const LABEL: &str = "com.qatlashub.ssh-browser";

/// The folder Windows runs the contents of at login.
///
/// Chosen over a Task Scheduler entry, and not for simplicity. `schtasks /Create /SC ONLOGON`
/// writes to the machine's task store, so it wants administrator rights — measured, on the
/// machine this was written for, with the task never created:
///
/// ```text
/// Error: schtasks failed: エラー: アクセスが拒否されました。
/// ```
///
/// Asking somebody to open an elevated prompt in order to start a program of their own is the
/// thing this command exists to avoid. This folder needs nothing, is where Windows itself
/// documents that login programs go, and is undone by deleting a file you can see.
fn startup_dir(home: &Path) -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("AppData").join("Roaming"))
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup")
}

/// Where the login entry lives, per platform.
///
/// Two of the three are fixed by convention; the third is ours to choose, so it goes beside
/// everything else the daemon remembers between runs.
fn entry_path(kind: Kind, home: &Path, state: &Path) -> PathBuf {
    // Kept in the signature though only the other two read it: a state directory is where the
    // Windows entry lived before `schtasks` turned out to need elevation, and a caller should
    // not have to know which platforms happen to want which directory today.
    let _ = state;
    match kind {
        Kind::Windows => startup_dir(home).join("ssh-browser.vbs"),
        Kind::MacOs => home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LABEL}.plist")),
        Kind::Systemd => home
            .join(".config")
            .join("systemd")
            .join("user")
            .join("ssh-browser.service"),
    }
}

/// What installing looks like on `kind`, for a daemon at `exe`.
pub fn install_plan(kind: Kind, exe: &Path, home: &Path, state: &Path) -> Plan {
    let entry = entry_path(kind, home, state);
    let exe = exe.display().to_string();
    match kind {
        Kind::Windows => Plan {
            // A one-line script, because Task Scheduler runs a console program in a console
            // window. Left visible that window sits there for the session, and the first thing
            // anybody does with a window they did not ask for is close it -- which kills the
            // daemon. `Run(..., 0, False)` is the documented way to start something with no
            // window at all, and one line of VBScript is a thing a suspicious reader can read.
            files: vec![(
                entry.clone(),
                format!("CreateObject(\"WScript.Shell\").Run \"\"\"{exe}\"\" serve\", 0, False\n"),
            )],
            // Nothing to run. Writing the file is the whole of it, which is also what makes
            // installing twice the same as installing once.
            commands: Vec::new(),
            remove: Vec::new(),
            note: format!(
                "ssh-browser will start when you log in.\n\
                 \x20 {}\n\n\
                 Undo with `ssh-browser autostart --off`, or delete that file.\n",
                entry.display()
            ),
        },
        Kind::MacOs => Plan {
            files: vec![(entry.clone(), launch_agent(&exe))],
            // `bootstrap` rather than the deprecated `load`, and into this user's own GUI
            // domain, so it asks for no password.
            commands: vec![vec![
                "launchctl".into(),
                "bootstrap".into(),
                format!("gui/{}", users_uid()),
                entry.display().to_string(),
            ]],
            remove: Vec::new(),
            note: format!(
                "ssh-browser will start when you log in.\n\
                 \x20 agent {}\n\n\
                 Undo with `ssh-browser autostart --off`.\n",
                entry.display()
            ),
        },
        Kind::Systemd => Plan {
            files: vec![(entry.clone(), user_unit(&exe))],
            commands: vec![
                vec!["systemctl".into(), "--user".into(), "daemon-reload".into()],
                vec![
                    "systemctl".into(),
                    "--user".into(),
                    "enable".into(),
                    "--now".into(),
                    "ssh-browser.service".into(),
                ],
            ],
            remove: Vec::new(),
            note: format!(
                "ssh-browser will start when you log in.\n\
                 \x20 unit {}\n\n\
                 On a machine you reach over ssh rather than log into, a user unit stops when\n\
                 your last session ends. `loginctl enable-linger` is what keeps it running.\n\n\
                 Undo with `ssh-browser autostart --off`.\n",
                entry.display()
            ),
        },
    }
}

/// What removing looks like.
///
/// A separate function rather than a flag on the first, because the commands are not the
/// install commands backwards.
pub fn remove_plan(kind: Kind, home: &Path, state: &Path) -> Plan {
    let entry = entry_path(kind, home, state);
    let note = "ssh-browser will no longer start when you log in. One running now keeps\n\
                running; stop it however you started it.\n"
        .to_string();
    match kind {
        Kind::Windows => Plan {
            files: Vec::new(),
            commands: Vec::new(),
            remove: vec![entry],
            note,
        },
        Kind::MacOs => Plan {
            files: Vec::new(),
            commands: vec![vec![
                "launchctl".into(),
                "bootout".into(),
                format!("gui/{}/{LABEL}", users_uid()),
            ]],
            remove: vec![entry],
            note,
        },
        Kind::Systemd => Plan {
            files: Vec::new(),
            commands: vec![vec![
                "systemctl".into(),
                "--user".into(),
                "disable".into(),
                "--now".into(),
                "ssh-browser.service".into(),
            ]],
            remove: vec![entry],
            note,
        },
    }
}

/// This account's user id, which launchd wants as part of the domain it is bootstrapped into.
///
/// Asked of `id -u` rather than through a libc binding, because that is one dependency for one
/// number. A wrong answer fails loudly at `launchctl` rather than quietly at login.
fn users_uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "501".to_string())
}

fn launch_agent(exe: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20 <key>Label</key>\n\
         \x20 <string>{LABEL}</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n\
         \x20   <string>{exe}</string>\n\
         \x20   <string>serve</string>\n\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key>\n\
         \x20 <true/>\n\
         \x20 <key>KeepAlive</key>\n\
         \x20 <true/>\n\
         </dict>\n\
         </plist>\n"
    )
}

fn user_unit(exe: &str) -> String {
    format!(
        "[Unit]\n\
         Description=ssh-browser, serving SSH hosts as browser origins\n\
         \n\
         [Service]\n\
         ExecStart={exe} serve\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// Do it, saying what was done as it happens.
///
/// Reported step by step rather than summarised at the end, because the step that fails is the
/// one worth naming and a summary printed afterwards never arrives.
pub fn apply(plan: &Plan) -> Result<()> {
    for (path, body) in &plan.files {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("making {}", parent.display()))?;
        }
        std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("  wrote {}", path.display());
    }

    for command in &plan.commands {
        let (program, args) = command.split_first().expect("a command has a program");
        eprintln!("  {}", command.join(" "));
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("running {program}"))?;
        if !out.status.success() {
            // Both streams: `schtasks` reports on stdout and `systemctl` on stderr, and a
            // failure that prints only the empty one is a failure with no reason attached.
            let said = [out.stdout, out.stderr]
                .iter()
                .map(|s| String::from_utf8_lossy(s).trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            bail!("{program} failed: {said}");
        }
    }

    for path in &plan.remove {
        match std::fs::remove_file(path) {
            Ok(()) => eprintln!("  removed {}", path.display()),
            // Already gone is the state that was wanted.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
    Ok(())
}

/// The home directory, which two of the three platforms put their login entry under.
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> (PathBuf, PathBuf) {
        (PathBuf::from("/home/you"), PathBuf::from("/state"))
    }

    const EVERY: [Kind; 3] = [Kind::Windows, Kind::MacOs, Kind::Systemd];

    /// Every platform, on whichever one happens to be running this. The whole reason `Kind` is
    /// an argument: two of the three are otherwise checked by nobody until somebody on that
    /// platform tries them, which is the wrong moment to find out.
    ///
    /// Not "and runs a command", which is what this said until Windows stopped needing one.
    /// What every platform has in common is the entry, and that it names the daemon by path.
    #[test]
    fn each_platform_writes_an_entry_naming_the_daemon() {
        let (home, state) = dirs();
        let exe = PathBuf::from("/bin/ssh-browser");
        for kind in EVERY {
            let plan = install_plan(kind, &exe, &home, &state);
            assert_eq!(plan.files.len(), 1, "{kind:?}");
            assert!(
                plan.remove.is_empty(),
                "{kind:?} installs, it does not delete"
            );
            // The daemon's own path, not a bare name: a login session's PATH is not a shell's,
            // and an entry that starts whatever `ssh-browser` it finds may find none.
            let (_, body) = &plan.files[0];
            assert!(body.contains("/bin/ssh-browser"), "{kind:?}: {body}");
            assert!(body.contains("serve"), "{kind:?}: {body}");
            assert!(plan.note.contains("autostart --off"), "{kind:?}");
        }
    }

    /// Removing undoes exactly what installing wrote.
    ///
    /// Compared as paths rather than by reading both functions, because the failure this
    /// prevents is silent: an uninstall that deletes a file nobody wrote leaves the login entry
    /// in place and reports success.
    #[test]
    fn removing_touches_what_installing_wrote() {
        let (home, state) = dirs();
        let exe = PathBuf::from("/bin/ssh-browser");
        for kind in EVERY {
            let installed = install_plan(kind, &exe, &home, &state);
            let removed = remove_plan(kind, &home, &state);
            assert_eq!(
                removed.remove,
                vec![installed.files[0].0.clone()],
                "{kind:?}"
            );
            assert!(removed.files.is_empty(), "{kind:?}");
        }
    }

    /// The Windows launcher hides its window, and that is load-bearing rather than tidy.
    #[test]
    fn the_windows_launcher_asks_for_no_window() {
        let (home, state) = dirs();
        let plan = install_plan(
            Kind::Windows,
            &PathBuf::from("C:/bin/ssh-browser.exe"),
            &home,
            &state,
        );
        let (path, body) = &plan.files[0];
        // The tail rather than the whole path: `APPDATA` is a real environment variable on the
        // machine running this and a roaming profile moves it, so asserting the prefix would be
        // asserting something about the test runner.
        assert!(
            path.ends_with("Start Menu/Programs/Startup/ssh-browser.vbs")
                || path.ends_with(r"Start Menu\Programs\Startup\ssh-browser.vbs"),
            "{path:?}"
        );
        // Nothing to run at all, which is the point of this location: no elevation, and
        // writing the file twice is the same as writing it once.
        assert!(plan.commands.is_empty(), "{:?}", plan.commands);
        assert!(
            body.contains(", 0, False"),
            "the window style must be hidden: {body}"
        );
        // Quoted, because a path with a space in it is the ordinary case on Windows and an
        // unquoted one runs the wrong program or none.
        assert!(body.contains("\"\"\"C:/bin/ssh-browser.exe\"\""), "{body}");
    }

    /// The launchd agent asks to be started at login, and is a plist launchd will accept.
    #[test]
    fn the_launch_agent_runs_at_load() {
        let (home, state) = dirs();
        let plan = install_plan(
            Kind::MacOs,
            &PathBuf::from("/bin/ssh-browser"),
            &home,
            &state,
        );
        let (path, body) = &plan.files[0];
        assert!(
            path.starts_with("/home/you/Library/LaunchAgents"),
            "{path:?}"
        );
        assert!(body.starts_with("<?xml"), "{body}");
        assert!(body.contains("<key>RunAtLoad</key>\n  <true/>"), "{body}");
        assert!(body.contains(LABEL), "{body}");
    }

    /// The systemd unit is wanted by the user's default target, which is what starts it.
    #[test]
    fn the_user_unit_is_wanted_by_default_target() {
        let (home, state) = dirs();
        let plan = install_plan(
            Kind::Systemd,
            &PathBuf::from("/bin/ssh-browser"),
            &home,
            &state,
        );
        let (path, body) = &plan.files[0];
        assert!(
            path.starts_with("/home/you/.config/systemd/user"),
            "{path:?}"
        );
        assert!(body.contains("WantedBy=default.target"), "{body}");
        assert!(body.contains("ExecStart=/bin/ssh-browser serve"), "{body}");
    }

    /// Installing twice is installing once, everywhere.
    ///
    /// Somebody unsure whether they did it already will do it again, and the answer has to be
    /// "you have it" rather than an error. Writing a file is idempotent on its own; the two
    /// platforms that also run something have to have chosen a command that is.
    #[test]
    fn installing_again_is_not_an_error() {
        let (home, state) = dirs();
        for kind in EVERY {
            let plan = install_plan(kind, &PathBuf::from("/bin/x"), &home, &state);
            for command in &plan.commands {
                let line = command.join(" ");
                let forgiving = line.contains("daemon-reload")
                    || line.contains("enable")
                    || line.contains("bootstrap");
                assert!(
                    forgiving,
                    "{kind:?} runs something that may refuse twice: {line}"
                );
            }
        }
    }
}
