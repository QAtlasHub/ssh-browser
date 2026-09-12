//! Concurrent SFTP access over a single stream.
//!
//! A Mutex around the stream would serialise every HTTP handler, turning a page's
//! N parallel subresource fetches back into N round trips — the exact failure this
//! exists to avoid. Instead two tasks own the stream and replies are demultiplexed
//! by request id, so any number of callers share one connection and their requests
//! coalesce into one flush.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use super::{Entry, RangeReq, RemoteFs};
use crate::sftp::transport::{self, SshChild};
use crate::sftp::wire::{
    Attrs, CLOSE, DATA, Dec, Enc, FXF_APPEND, FXF_CREAT, FXF_READ, FXF_WRITE, HANDLE, MKDIR, NAME,
    OPEN, OPENDIR, READ, READDIR, STATUS, STATUS_EOF, STATUS_OK, WRITE, owner_of_longname,
};
use crate::sftp::{Reply, Rx, Sftp, Tx};

const QUEUE_DEPTH: usize = 1024;
const MAX_BATCH: usize = 256;
const READ_CHUNK: u32 = 32 * 1024;
const WRITE_CHUNK: usize = 32 * 1024;

/// How long the writer waits for sibling callers before committing to a flush.
/// Against a 16 ms RTT this costs roughly 1%, and it is what collapses N
/// concurrent handler calls into one round trip even when they did not arrive
/// together through `read_batch`.
const COALESCE: Duration = Duration::from_micros(200);

struct Job {
    kind: u8,
    /// Request body without the leading id; the writer owns id allocation.
    body: Vec<u8>,
    reply: oneshot::Sender<Reply>,
}

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Reply>>>>;

pub struct SftpFs {
    jobs: mpsc::Sender<Job>,
    round_trips: Arc<AtomicU64>,
    /// Dropping this kills ssh, which closes both pipes and fails pending callers.
    _child: Option<SshChild>,
}

impl SftpFs {
    pub async fn connect(host: &str) -> Result<Self> {
        let (child, w, r) = transport::open(host)?;
        let sftp = Sftp::handshake(w, r).await?;
        Ok(Self::drive(sftp, Some(child)))
    }

    /// Drive a session over arbitrary streams. Exists so the round-trip invariant
    /// can be asserted against an in-memory server, with no ssh anywhere.
    pub async fn over<W, R>(w: W, r: R) -> Result<Self>
    where
        W: AsyncWrite + Unpin + Send + 'static,
        R: AsyncRead + Unpin + Send + 'static,
    {
        let sftp = Sftp::handshake(w, r).await?;
        Ok(Self::drive(sftp, None))
    }

    fn drive<W, R>(sftp: Sftp<W, R>, child: Option<SshChild>) -> Self
    where
        W: AsyncWrite + Unpin + Send + 'static,
        R: AsyncRead + Unpin + Send + 'static,
    {
        let (tx, rx) = sftp.into_halves();
        let (jobs, job_rx) = mpsc::channel(QUEUE_DEPTH);
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let round_trips = Arc::new(AtomicU64::new(0));

        tokio::spawn(writer(
            tx,
            job_rx,
            Arc::clone(&pending),
            Arc::clone(&round_trips),
        ));
        tokio::spawn(reader(rx, pending));

        Self {
            jobs,
            round_trips,
            _child: child,
        }
    }

    /// Hand a request to the writer without awaiting its reply.
    async fn issue(&self, kind: u8, body: Vec<u8>) -> Result<oneshot::Receiver<Reply>> {
        let (reply, rx) = oneshot::channel();
        self.jobs
            .send(Job { kind, body, reply })
            .await
            .map_err(|_| anyhow!("sftp session is gone"))?;
        Ok(rx)
    }
}

async fn await_reply(rx: oneshot::Receiver<Reply>) -> Result<Reply> {
    rx.await
        .map_err(|_| anyhow!("sftp session closed before replying"))
}

/// Decode one SSH_FXP_NAME page.
fn decode_names(payload: &[u8]) -> Result<Vec<Entry>> {
    let mut d = Dec::new(payload);
    let count = d.u32().context("readdir count")?;
    // A count is a length prefix from the far end, so it is not trusted enough to
    // size an allocation with.
    ensure!(count <= 1 << 16, "implausible readdir count {count}");
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name = String::from_utf8_lossy(d.str().context("filename")?).into_owned();
        // The longname is the only place a v3 listing carries the owner's *name*. The
        // attrs carry a numeric uid, which cannot be compared with an account name
        // without a passwd lookup the sftp subsystem has no way to perform.
        let longname = String::from_utf8_lossy(d.str().context("longname")?).into_owned();
        let owner = owner_of_longname(&longname).map(str::to_string);
        let attrs = Attrs::decode(&mut d).context("attrs")?;
        out.push(Entry { name, attrs, owner });
    }
    Ok(out)
}

fn handle_from(r: &Reply, what: &str) -> Result<Vec<u8>> {
    ensure!(r.kind == HANDLE, "{what} refused (reply type {})", r.kind);
    Ok(Dec::new(r.payload()).str().context("handle")?.to_vec())
}

impl RemoteFs for SftpFs {
    async fn read_batch(&self, paths: &[String]) -> Vec<Result<Vec<u8>>> {
        // Every open is issued before any reply is awaited. That ordering is the
        // whole mechanism; awaiting inside this loop would cost paths.len() round
        // trips instead of one.
        let mut opens = Vec::with_capacity(paths.len());
        for p in paths {
            opens.push(
                self.issue(
                    OPEN,
                    Enc::new().str(p.as_bytes()).u32(FXF_READ).u32(0).done(),
                )
                .await,
            );
        }

        let mut handles: Vec<Option<Vec<u8>>> = Vec::with_capacity(paths.len());
        let mut out: Vec<Result<Vec<u8>>> = Vec::with_capacity(paths.len());
        for (rx, path) in opens.into_iter().zip(paths) {
            let opened = match rx {
                Ok(rx) => await_reply(rx).await.and_then(|r| handle_from(&r, path)),
                Err(e) => Err(e),
            };
            match opened {
                Ok(h) => {
                    handles.push(Some(h));
                    out.push(Ok(Vec::new()));
                }
                Err(e) => {
                    handles.push(None);
                    out.push(Err(e));
                }
            }
        }

        // Chunk index k for every still-live file goes out together, so this loop
        // costs one round trip per chunk index rather than one per file.
        let mut live: Vec<usize> = (0..paths.len()).filter(|&i| handles[i].is_some()).collect();
        while !live.is_empty() {
            let mut rxs = Vec::with_capacity(live.len());
            for &i in &live {
                let handle = handles[i].as_ref().expect("live implies a handle");
                let offset = out[i].as_ref().map_or(0, Vec::len) as u64;
                rxs.push(
                    self.issue(
                        READ,
                        Enc::new().str(handle).u64(offset).u32(READ_CHUNK).done(),
                    )
                    .await,
                );
            }

            let mut still_live = Vec::new();
            for (&i, rx) in live.iter().zip(rxs) {
                let chunk = match rx {
                    Ok(rx) => await_reply(rx).await,
                    Err(e) => Err(e),
                };
                match chunk {
                    Ok(r) if r.kind == DATA => {
                        let data = Dec::new(r.payload()).str().unwrap_or(&[]).to_vec();
                        let full = data.len() as u32 == READ_CHUNK;
                        if let Ok(buf) = &mut out[i] {
                            buf.extend_from_slice(&data);
                        }
                        if full {
                            still_live.push(i);
                        }
                    }
                    // A STATUS is EOF only when it says so. Treating every
                    // STATUS as end-of-file hands back an empty success for a
                    // directory, whose open succeeds and whose read fails --
                    // exactly the silent success invariant 4 forbids.
                    Ok(r) if r.kind == STATUS => {
                        let code = Dec::new(r.payload()).u32().unwrap_or(u32::MAX);
                        if code != STATUS_EOF {
                            out[i] = Err(anyhow!("read failed with sftp status {code}"));
                        }
                    }
                    Ok(r) => out[i] = Err(anyhow!("read gave reply type {}", r.kind)),
                    Err(e) => out[i] = Err(e),
                }
            }
            live = still_live;
        }

        for handle in handles.iter().flatten() {
            let _ = self.issue(CLOSE, Enc::new().str(handle).done()).await;
        }
        out
    }

    async fn read_ranges(&self, reqs: &[RangeReq]) -> Vec<Result<Vec<u8>>> {
        let mut opens = Vec::with_capacity(reqs.len());
        for r in reqs {
            opens.push(
                self.issue(
                    OPEN,
                    Enc::new()
                        .str(r.path.as_bytes())
                        .u32(FXF_READ)
                        .u32(0)
                        .done(),
                )
                .await,
            );
        }

        let mut handles: Vec<Option<Vec<u8>>> = Vec::with_capacity(reqs.len());
        let mut out: Vec<Result<Vec<u8>>> = Vec::with_capacity(reqs.len());
        for (rx, r) in opens.into_iter().zip(reqs) {
            let opened = match rx {
                Ok(rx) => await_reply(rx)
                    .await
                    .and_then(|reply| handle_from(&reply, &r.path)),
                Err(e) => Err(e),
            };
            match opened {
                Ok(h) => {
                    handles.push(Some(h));
                    out.push(Ok(Vec::new()));
                }
                Err(e) => {
                    handles.push(None);
                    out.push(Err(e));
                }
            }
        }

        // Chunk every range up front and issue the whole set at once. A one-megabyte
        // range is thirty-two reads; sending them one at a time would cost
        // thirty-two round trips and put the invariant back where it started.
        struct Piece {
            req: usize,
            offset: u64,
            len: u32,
        }
        let mut pieces = Vec::new();
        for (i, r) in reqs.iter().enumerate() {
            if handles[i].is_none() {
                continue;
            }
            let mut at = r.offset;
            let end = r.offset.saturating_add(r.len);
            while at < end {
                let len =
                    u32::try_from((end - at).min(u64::from(READ_CHUNK))).unwrap_or(READ_CHUNK);
                pieces.push(Piece {
                    req: i,
                    offset: at,
                    len,
                });
                at += u64::from(len);
            }
        }

        let mut rxs = Vec::with_capacity(pieces.len());
        for p in &pieces {
            let handle = handles[p.req].as_ref().expect("pieces skip failed opens");
            rxs.push(
                self.issue(READ, Enc::new().str(handle).u64(p.offset).u32(p.len).done())
                    .await,
            );
        }

        // Replies are reassembled in issue order, which is offset order within each
        // request, so a short read at end of file simply ends that request's data.
        for (p, rx) in pieces.iter().zip(rxs) {
            let reply = match rx {
                Ok(rx) => await_reply(rx).await,
                Err(e) => Err(e),
            };
            match reply {
                Ok(r) if r.kind == DATA => {
                    let data = Dec::new(r.payload()).str().unwrap_or(&[]).to_vec();
                    if let Ok(buf) = &mut out[p.req] {
                        buf.extend_from_slice(&data);
                    }
                }
                // EOF inside a requested range is not a failure: the file is simply
                // shorter than the client asked for, and the caller sees that in the
                // length of what comes back.
                Ok(r) if r.kind == STATUS => {
                    let code = Dec::new(r.payload()).u32().unwrap_or(u32::MAX);
                    if code != STATUS_EOF {
                        out[p.req] = Err(anyhow!("read failed with sftp status {code}"));
                    }
                }
                Ok(r) => out[p.req] = Err(anyhow!("read gave reply type {}", r.kind)),
                Err(e) => out[p.req] = Err(e),
            }
        }

        for handle in handles.iter().flatten() {
            let _ = self.issue(CLOSE, Enc::new().str(handle).done()).await;
        }
        out
    }

    async fn append(&self, path: &str, bytes: &[u8]) -> Result<()> {
        // WRITE | APPEND | CREAT. In append mode the server ignores the offset in each
        // WRITE and places the data at the end, which is what makes this safe for a
        // single writer with no lock at all. It would not be safe for two, and the
        // annotation format is per-author logs precisely so that there are never two.
        let opened = await_reply(
            self.issue(
                OPEN,
                Enc::new()
                    .str(path.as_bytes())
                    .u32(FXF_WRITE | FXF_APPEND | FXF_CREAT)
                    .u32(0)
                    .done(),
            )
            .await?,
        )
        .await?;
        let handle = handle_from(&opened, path)?;

        // Chunked and issued together, for the same reason reads are.
        let mut rxs = Vec::new();
        let mut at = 0usize;
        while at < bytes.len() {
            let end = at.saturating_add(WRITE_CHUNK).min(bytes.len());
            rxs.push(
                self.issue(
                    WRITE,
                    Enc::new()
                        .str(&handle)
                        .u64(at as u64)
                        .str(&bytes[at..end])
                        .done(),
                )
                .await?,
            );
            at = end;
        }

        // Every reply is drained before returning, and any failure is kept. A write that
        // reported an error and was treated as success would lose an annotation while
        // telling the user it was saved.
        let mut failure = None;
        for rx in rxs {
            match await_reply(rx).await {
                Ok(r) => {
                    let code = Dec::new(r.payload()).u32().unwrap_or(u32::MAX);
                    if r.kind != STATUS || code != STATUS_OK {
                        failure = Some(anyhow!("writing {path} failed with sftp status {code}"));
                    }
                }
                Err(e) => failure = Some(e),
            }
        }

        let _ = self.issue(CLOSE, Enc::new().str(&handle).done()).await;
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn mkdirs(&self, path: &str) -> Result<()> {
        let mut levels = Vec::new();
        let mut at = String::new();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            at.push('/');
            at.push_str(part);
            levels.push(at.clone());
        }

        let mut rxs = Vec::with_capacity(levels.len());
        for level in &levels {
            rxs.push(
                self.issue(MKDIR, Enc::new().str(level.as_bytes()).u32(0).done())
                    .await?,
            );
        }
        for rx in rxs {
            // Ignored on purpose. "Already exists" and "created" are both acceptable
            // outcomes here and servers do not report them distinguishably.
            let _ = await_reply(rx).await;
        }

        // The only check worth making: is it a directory now? Trusting the mkdir replies
        // would report success for a path that is not there, which is the failure mode
        // this whole codebase is trying not to have.
        let one = [path.to_string()];
        let mut got = self.list_dirs(&one).await;
        match got.pop() {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(e.context(format!("creating {path}"))),
            None => Err(anyhow!("list_dirs returned nothing for {path}")),
        }
    }

    async fn list_dirs(&self, paths: &[String]) -> Vec<Result<Vec<Entry>>> {
        // Every opendir goes out before any reply is awaited, for the same reason
        // read_batch does it. A symlink check walks a whole path, and one round
        // trip per component would put that walk back inside the per-request
        // budget the origin layer cannot afford.
        let mut opens = Vec::with_capacity(paths.len());
        for p in paths {
            opens.push(
                self.issue(OPENDIR, Enc::new().str(p.as_bytes()).done())
                    .await,
            );
        }

        let mut handles: Vec<Option<Vec<u8>>> = Vec::with_capacity(paths.len());
        let mut out: Vec<Result<Vec<Entry>>> = Vec::with_capacity(paths.len());
        for (rx, path) in opens.into_iter().zip(paths) {
            let opened = match rx {
                Ok(rx) => await_reply(rx).await.and_then(|r| handle_from(&r, path)),
                Err(e) => Err(e),
            };
            match opened {
                Ok(h) => {
                    handles.push(Some(h));
                    out.push(Ok(Vec::new()));
                }
                Err(e) => {
                    handles.push(None);
                    out.push(Err(e));
                }
            }
        }

        // A readdir returns one page at a time, so page k for every still-open
        // directory is issued together: one round trip per page index rather than
        // one per directory.
        let mut live: Vec<usize> = (0..paths.len()).filter(|&i| handles[i].is_some()).collect();
        while !live.is_empty() {
            let mut rxs = Vec::with_capacity(live.len());
            for &i in &live {
                let handle = handles[i].as_ref().expect("live implies a handle");
                rxs.push(self.issue(READDIR, Enc::new().str(handle).done()).await);
            }

            let mut still_live = Vec::new();
            for (&i, rx) in live.iter().zip(rxs) {
                let page = match rx {
                    Ok(rx) => await_reply(rx).await,
                    Err(e) => Err(e),
                };
                match page {
                    Ok(r) if r.kind == NAME => match decode_names(r.payload()) {
                        Ok(entries) => {
                            if let Ok(acc) = &mut out[i] {
                                acc.extend(entries);
                            }
                            still_live.push(i);
                        }
                        Err(e) => out[i] = Err(e),
                    },
                    // A STATUS ends the listing only when it says EOF. Accepting
                    // any status as the end returns a short listing as a success,
                    // which is the same silent success read_batch had: a directory
                    // we were refused would read as an empty directory.
                    Ok(r) if r.kind == STATUS => {
                        let code = Dec::new(r.payload()).u32().unwrap_or(u32::MAX);
                        if code != STATUS_EOF {
                            out[i] = Err(anyhow!("readdir failed with sftp status {code}"));
                        }
                    }
                    Ok(r) => out[i] = Err(anyhow!("readdir gave reply type {}", r.kind)),
                    Err(e) => out[i] = Err(e),
                }
            }
            live = still_live;
        }

        for handle in handles.iter().flatten() {
            let _ = self.issue(CLOSE, Enc::new().str(handle).done()).await;
        }
        out
    }

    fn round_trips(&self) -> u64 {
        self.round_trips.load(Ordering::Relaxed)
    }
}

async fn writer<W: AsyncWrite + Unpin>(
    mut tx: Tx<W>,
    mut jobs: mpsc::Receiver<Job>,
    pending: Pending,
    round_trips: Arc<AtomicU64>,
) {
    let mut batch: Vec<Job> = Vec::with_capacity(MAX_BATCH);
    loop {
        if jobs.recv_many(&mut batch, MAX_BATCH).await == 0 {
            return;
        }
        if batch.len() < MAX_BATCH {
            tokio::time::sleep(COALESCE).await;
            while batch.len() < MAX_BATCH {
                match jobs.try_recv() {
                    Ok(job) => batch.push(job),
                    Err(_) => break,
                }
            }
        }

        for job in batch.drain(..) {
            let id = tx.alloc_id();
            let mut payload = Vec::with_capacity(4 + job.body.len());
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&job.body);
            // Registered before the write, because the reply can land the instant
            // we flush.
            pending
                .lock()
                .expect("pending map poisoned")
                .insert(id, job.reply);
            if tx.queue(job.kind, &payload).await.is_err() {
                return;
            }
        }

        if tx.flush().await.is_err() {
            return;
        }
        round_trips.fetch_add(1, Ordering::Relaxed);
    }
}

async fn reader<R: AsyncRead + Unpin>(mut rx: Rx<R>, pending: Pending) {
    while let Ok(reply) = rx.recv().await {
        let waiter = pending
            .lock()
            .expect("pending map poisoned")
            .remove(&reply.id);
        if let Some(waiter) = waiter {
            let _ = waiter.send(reply);
        }
    }
    // The stream is finished. Dropping the senders makes every awaiting caller
    // fail, rather than hang forever on a reply that can no longer arrive.
    pending.lock().expect("pending map poisoned").clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sftp::wire::{INIT, VERSION};
    use crate::sftp::{read_frame, write_frame};
    use tokio::io::AsyncWriteExt;

    /// Just enough sftp server to answer the calls `read_batch` makes. Every file
    /// has the same body.
    async fn fake_server<R, W>(mut r: R, mut w: W, body: Vec<u8>, fail_read: bool)
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let (kind, _) = read_frame(&mut r).await.expect("init frame");
        assert_eq!(kind, INIT);
        write_frame(&mut w, VERSION, &Enc::new().u32(3).done())
            .await
            .expect("version");
        w.flush().await.expect("flush version");

        while let Ok((kind, payload)) = read_frame(&mut r).await {
            let mut d = Dec::new(&payload);
            let id = d.u32().expect("request id");
            let (out_kind, out) = match kind {
                OPEN => (HANDLE, Enc::new().u32(id).str(b"h").done()),
                READ => {
                    d.str().expect("handle");
                    let offset = d.u64().expect("offset") as usize;
                    if fail_read {
                        // SSH_FX_FAILURE, which is what reading a directory gives.
                        (
                            STATUS,
                            Enc::new()
                                .u32(id)
                                .u32(4)
                                .str(b"is a directory")
                                .str(b"")
                                .done(),
                        )
                    } else if offset >= body.len() {
                        (
                            STATUS,
                            Enc::new().u32(id).u32(1).str(b"eof").str(b"").done(),
                        )
                    } else {
                        (DATA, Enc::new().u32(id).str(&body[offset..]).done())
                    }
                }
                CLOSE => (STATUS, Enc::new().u32(id).u32(0).str(b"ok").str(b"").done()),
                other => panic!("fake server got unexpected request type {other}"),
            };
            write_frame(&mut w, out_kind, &out).await.expect("reply");
            w.flush().await.expect("flush reply");
        }
    }

    /// Invariant 1, with no network involved: forty files must not cost forty round
    /// trips. This is the test that fails if anyone ever "simplifies" read_batch
    /// into a loop that awaits each open.
    #[tokio::test]
    async fn forty_reads_cost_a_constant_number_of_round_trips() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (cr, cw) = tokio::io::split(client);
        let (sr, sw) = tokio::io::split(server);
        tokio::spawn(fake_server(sr, sw, b"hello".to_vec(), false));

        let fs = SftpFs::over(cw, cr).await.expect("handshake");
        let paths: Vec<String> = (0..40).map(|i| format!("/f{i}")).collect();
        let out = tokio::time::timeout(Duration::from_secs(10), fs.read_batch(&paths))
            .await
            .expect("read_batch should not hang");

        assert_eq!(out.len(), 40);
        for r in &out {
            assert_eq!(r.as_ref().expect("read succeeded").as_slice(), b"hello");
        }

        // One flush for the opens, one for the reads, one for the closes. The
        // number that must not move is that it does not scale with 40.
        let trips = fs.round_trips();
        assert!(trips <= 6, "forty files cost {trips} round trips");
    }

    /// Regression: found on a real host, not in a test. A directory's open
    /// succeeds and its read fails, and treating that STATUS as EOF returned an
    /// empty 200 instead of letting the caller fall through to a listing.
    #[tokio::test]
    async fn a_failed_read_is_not_reported_as_an_empty_success() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let (cr, cw) = tokio::io::split(client);
        let (sr, sw) = tokio::io::split(server);
        tokio::spawn(fake_server(sr, sw, b"unused".to_vec(), true));

        let fs = SftpFs::over(cw, cr).await.expect("handshake");
        let out = tokio::time::timeout(
            Duration::from_secs(10),
            fs.read_batch(&["/a-directory".to_string()]),
        )
        .await
        .expect("read_batch should not hang");

        assert!(
            out[0].is_err(),
            "a read that failed must not look like an empty file"
        );
    }

    /// Invariant 4: a session that dies must surface as an error. Hanging forever
    /// on a reply that can never arrive is the worst failure available.
    #[tokio::test]
    async fn a_dead_session_fails_callers_instead_of_hanging() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let (cr, cw) = tokio::io::split(client);
        let (mut sr, mut sw) = tokio::io::split(server);
        tokio::spawn(async move {
            read_frame(&mut sr).await.expect("init frame");
            write_frame(&mut sw, VERSION, &Enc::new().u32(3).done())
                .await
                .expect("version");
            sw.flush().await.expect("flush version");
            // Then vanish, mid-conversation.
        });

        let fs = SftpFs::over(cw, cr).await.expect("handshake");
        let out = tokio::time::timeout(Duration::from_secs(10), fs.read_batch(&["/a".to_string()]))
            .await
            .expect("a dead session must not hang the caller");

        assert!(out[0].is_err(), "a closed session must surface as an error");
    }
}
