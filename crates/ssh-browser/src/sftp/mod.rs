//! SFTP client whose send and receive halves are deliberately separate.
//!
//! `queue` does not await a reply. That is the entire point. A page needs N
//! subresources, and issuing all N requests before reading any reply is what
//! holds the remote round trips at O(1) instead of O(N). An API that pairs one
//! request with one response — which is what every convenient sftp wrapper
//! offers — makes that invariant unreachable, so this layer does not provide one.

pub mod transport;
pub mod wire;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use transport::SshTransport;
use wire::{Dec, Enc, INIT, VERSION};

const MAX_FRAME: usize = 64 * 1024 * 1024;

pub struct Reply {
    pub id: u32,
    pub kind: u8,
    body: Vec<u8>,
}

impl Reply {
    /// Body past the leading request id.
    pub fn payload(&self) -> &[u8] {
        &self.body[4..]
    }
}

pub struct Sftp {
    t: SshTransport,
    next_id: u32,
    version: u32,
}

impl Sftp {
    pub async fn connect(host: &str) -> Result<Self> {
        let mut s = Self {
            t: SshTransport::open(host)?,
            next_id: 1,
            version: 0,
        };

        s.queue(INIT, &Enc::new().u32(3).done()).await?;
        s.flush().await?;

        let (kind, body) = s.read_frame().await?;
        ensure!(kind == VERSION, "expected SSH_FXP_VERSION, got type {kind}");
        s.version = Dec::new(&body).u32().context("malformed SSH_FXP_VERSION")?;
        ensure!(
            s.version >= 3,
            "remote speaks sftp v{}, need v3 or later",
            s.version
        );
        Ok(s)
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    /// Buffers one request. Nothing reaches the wire until [`Sftp::flush`].
    pub async fn queue(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        let len = u32::try_from(payload.len() + 1).context("sftp request too large")?;
        self.t.w.write_all(&len.to_be_bytes()).await?;
        self.t.w.write_all(&[kind]).await?;
        self.t.w.write_all(payload).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.t.w.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Reply> {
        let (kind, body) = self.read_frame().await?;
        ensure!(body.len() >= 4, "reply type {kind} carries no request id");
        let id = u32::from_be_bytes(body[..4].try_into().expect("length checked above"));
        Ok(Reply { id, kind, body })
    }

    async fn read_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut head = [0u8; 5];
        self.t.r.read_exact(&mut head).await?;
        let len = u32::from_be_bytes(head[..4].try_into().expect("fixed size")) as usize;
        if len == 0 || len > MAX_FRAME {
            bail!("implausible sftp frame length {len}");
        }
        let mut body = vec![0u8; len - 1];
        self.t.r.read_exact(&mut body).await?;
        Ok((head[4], body))
    }
}
