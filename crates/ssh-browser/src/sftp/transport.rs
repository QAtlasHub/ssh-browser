//! Transport is `ssh <host> -s sftp`.
//!
//! OpenSSH owns ssh_config, so ProxyJump, non-standard ports, agent keys and
//! certificates work without reimplementation. rclone's sftp backend cannot read
//! ssh_config (rclone#6987), which is why it fails on any host behind a jump box;
//! borrowing the system ssh removes that whole class of bug.

use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::io::{BufReader, BufWriter};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Large enough that a whole batch of requests lands in a single write.
const WRITE_BUF: usize = 256 * 1024;

/// Holds the ssh process. Dropping it kills the child, which closes both pipes and
/// makes every pending caller fail rather than hang.
pub struct SshChild(#[allow(dead_code)] Child);

type Halves = (SshChild, BufWriter<ChildStdin>, BufReader<ChildStdout>);

pub fn open(host: &str) -> Result<Halves> {
    let mut child = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(host)
        .arg("-s")
        .arg("sftp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("spawn ssh: is the OpenSSH client on PATH?")?;

    let stdin = child.stdin.take().context("ssh stdin was not piped")?;
    let stdout = child.stdout.take().context("ssh stdout was not piped")?;

    Ok((
        SshChild(child),
        BufWriter::with_capacity(WRITE_BUF, stdin),
        BufReader::new(stdout),
    ))
}
