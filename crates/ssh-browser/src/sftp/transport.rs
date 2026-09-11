//! Transport is `ssh <host> -s sftp`.
//!
//! OpenSSH owns ssh_config, so ProxyJump, non-standard ports, agent keys and
//! certificates work without us reimplementing any of them. rclone's sftp
//! backend cannot read ssh_config (rclone#6987), which is why it fails on hosts
//! behind a jump box; borrowing the system ssh removes that whole class of bug.

use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::io::{BufReader, BufWriter};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Large enough that a whole batch of requests lands in one write.
const WRITE_BUF: usize = 256 * 1024;

pub struct SshTransport {
    /// Held so the child is killed when the transport drops.
    _child: Child,
    pub w: BufWriter<ChildStdin>,
    pub r: BufReader<ChildStdout>,
}

impl SshTransport {
    pub fn open(host: &str) -> Result<Self> {
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

        Ok(Self {
            _child: child,
            w: BufWriter::with_capacity(WRITE_BUF, stdin),
            r: BufReader::new(stdout),
        })
    }
}
