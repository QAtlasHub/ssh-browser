//! SFTP framing with the send and receive halves deliberately separate.
//!
//! Nothing here pairs a request with its reply. That is the entire point. A page
//! needs N subresources, and issuing all N requests before reading any reply is
//! what holds the remote round trips at O(1) instead of O(N). An API that pairs
//! one call to one reply — what every convenient sftp wrapper offers — puts that
//! invariant out of reach, so this layer does not provide one.
//!
//! [`Sftp`] is the sequential form, used by the measurement binary. For concurrent
//! callers the halves are split apart and driven by tasks; see `crate::fs::sftp`.

pub mod transport;
pub mod wire;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len() + 1).context("sftp request too large")?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&[kind]).await?;
    w.write_all(payload).await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head).await?;
    let len = u32::from_be_bytes(head[..4].try_into().expect("fixed size")) as usize;
    if len == 0 || len > MAX_FRAME {
        bail!("implausible sftp frame length {len}");
    }
    let mut body = vec![0u8; len - 1];
    r.read_exact(&mut body).await?;
    Ok((head[4], body))
}

/// Write half. `queue` buffers; only `flush` reaches the wire, so one flush can
/// carry an arbitrary number of requests.
pub struct Tx<W> {
    w: W,
    next_id: u32,
}

impl<W: AsyncWrite + Unpin> Tx<W> {
    pub fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    pub async fn queue(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.w, kind, payload).await
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.w.flush().await?;
        Ok(())
    }
}

/// Read half. Replies arrive in whatever order the server finishes them, which is
/// why every reply carries the request id back.
pub struct Rx<R> {
    r: R,
}

impl<R: AsyncRead + Unpin> Rx<R> {
    pub async fn recv(&mut self) -> Result<Reply> {
        let (kind, body) = read_frame(&mut self.r).await?;
        ensure!(body.len() >= 4, "reply type {kind} carries no request id");
        let id = u32::from_be_bytes(body[..4].try_into().expect("length checked above"));
        Ok(Reply { id, kind, body })
    }
}

pub struct Sftp<W, R> {
    tx: Tx<W>,
    rx: Rx<R>,
    version: u32,
}

impl<W: AsyncWrite + Unpin, R: AsyncRead + Unpin> Sftp<W, R> {
    pub async fn handshake(w: W, r: R) -> Result<Self> {
        let mut tx = Tx { w, next_id: 1 };
        let mut rx = Rx { r };

        write_frame(&mut tx.w, INIT, &Enc::new().u32(3).done()).await?;
        tx.flush().await?;

        let (kind, body) = read_frame(&mut rx.r).await?;
        ensure!(kind == VERSION, "expected SSH_FXP_VERSION, got type {kind}");
        let version = Dec::new(&body).u32().context("malformed SSH_FXP_VERSION")?;
        ensure!(
            version >= 3,
            "remote speaks sftp v{version}, need v3 or later"
        );

        Ok(Self { tx, rx, version })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn alloc_id(&mut self) -> u32 {
        self.tx.alloc_id()
    }

    pub async fn queue(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        self.tx.queue(kind, payload).await
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.tx.flush().await
    }

    pub async fn recv(&mut self) -> Result<Reply> {
        self.rx.recv().await
    }

    /// Hand the halves to separate tasks so concurrent callers can share one stream.
    pub fn into_halves(self) -> (Tx<W>, Rx<R>) {
        (self.tx, self.rx)
    }
}
