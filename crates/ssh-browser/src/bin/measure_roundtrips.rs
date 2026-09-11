//! Measures the invariant the product rests on: remote round trips for one page
//! must not grow with the number of subresources.
//!
//! Wall-clock milliseconds alone would be meaningless because they move with the
//! network. So one round trip (tau) is measured first and every batch is reported
//! as a multiple of it. A pipelined batch of N opens costs about 1 tau; a serial
//! one costs about N. Reads are reported too, but they carry the file as well as
//! the request, so their cost is transfer time as much as round trips and the
//! verdict does not rest on them.
//!
//! usage: `measure-roundtrips <ssh-host> [remote-dir]`

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use ssh_browser::sftp::wire::{
    Attrs, CLOSE, DATA, Dec, Enc, FXF_READ, HANDLE, NAME, OPEN, OPENDIR, READ, READDIR, REALPATH,
    STATUS,
};
use ssh_browser::sftp::{Sftp, transport};
use tokio::io::{BufReader, BufWriter};
use tokio::process::{ChildStdin, ChildStdout};

/// The concrete session this binary drives: sftp over the system ssh client.
type Session = Sftp<BufWriter<ChildStdin>, BufReader<ChildStdout>>;

const BATCH_SIZES: [usize; 4] = [1, 8, 20, 40];
const READ_LEN: u32 = 32 * 1024;
const TAU_REPS: usize = 7;

/// A batch counts as pipelined if its opens cost under a quarter of the serial
/// price. Only opens: see the verdict below for why reads cannot carry it.
const PIPELINE_MARGIN: f64 = 4.0;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let host = args
        .next()
        .context("usage: measure-roundtrips <ssh-host> [remote-dir]")?;
    let dir = args.next().unwrap_or_else(|| "/usr/include".to_string());

    let (_child, w, r) = transport::open(&host)?;
    let mut s = Sftp::handshake(w, r).await?;
    println!("host {host}  sftp v{}", s.version());

    let tau = measure_tau(&mut s).await?;
    println!("tau (one round trip) = {:.1} ms", ms(tau));

    let entries = list(&mut s, &dir).await?;
    let files: Vec<String> = entries
        .iter()
        .filter(|(name, a)| {
            !a.is_dir() && !a.is_symlink() && a.size.unwrap_or(0) > 0 && name != "." && name != ".."
        })
        .map(|(name, _)| format!("{}/{}", dir.trim_end_matches('/'), name))
        .collect();
    ensure!(
        !files.is_empty(),
        "no regular non-empty files in {dir}; pass a different remote-dir"
    );
    println!(
        "{} entries in {dir}, {} usable files",
        entries.len(),
        files.len()
    );
    println!();

    let mut largest = 0usize;
    let mut largest_open = 0.0f64;
    let mut largest_read = 0.0f64;
    let mut prev_read = 0.0f64;
    let mut last_read = 0.0f64;
    for n in BATCH_SIZES {
        if n > files.len() {
            continue;
        }
        let batch = &files[..n];
        let (t_open, handles) = batch_open(&mut s, batch).await?;
        let (t_read, bytes) = batch_read(&mut s, &handles).await?;
        batch_close(&mut s, &handles).await?;

        let open_tau = t_open.as_secs_f64() / tau.as_secs_f64();
        let read_tau = t_read.as_secs_f64() / tau.as_secs_f64();
        println!(
            "n={n:<3} open {:>7.1} ms ({open_tau:>5.2} tau)   read {:>7.1} ms ({read_tau:>5.2} tau)   {bytes} B",
            ms(t_open),
            ms(t_read)
        );
        largest = n;
        largest_open = open_tau;
        largest_read = read_tau;
        if n > 1 {
            prev_read = last_read;
        }
        last_read = read_tau;
    }

    println!();
    ensure!(
        largest > 1,
        "only one usable file; cannot distinguish pipelined from serial"
    );
    // The verdict rests on opens alone. An open carries a path and nothing else, so
    // its cost is round trips and only round trips. A read also carries the file,
    // and under an injected per-packet delay the transfer dominates: 400 KB reads
    // as 15 tau however few round trips fetched it. Judging on reads made this
    // check fail on how much data the chosen directory happens to hold, which is
    // a property of the machine rather than of the code -- exactly the kind of
    // flaky gate that teaches people to ignore a red check.
    //
    // Reads still say something, just not in absolute terms: if doubling the batch
    // does not double the time, the round trips did not scale either.
    if prev_read > 0.0 {
        let growth = largest_read / prev_read;
        println!(
            "reads {largest_read:.2} tau at n={largest}, {growth:.2}x the previous batch (serial would be about 2x)"
        );
    }

    let serial = largest as f64;
    if largest_open < serial / PIPELINE_MARGIN {
        println!(
            "VERDICT pipelined: opens cost {largest_open:.2} tau at n={largest} (serial would cost about {serial:.0})"
        );
        Ok(())
    } else {
        bail!(
            "VERDICT serial: opens cost {largest_open:.2} tau at n={largest}, near the serial cost {serial:.0}. Invariant 1 (O(1) round trips per page) is not reachable over this transport."
        )
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// One REALPATH is the cheapest honest round trip the protocol offers.
async fn measure_tau(s: &mut Session) -> Result<Duration> {
    let mut samples = Vec::with_capacity(TAU_REPS);
    for _ in 0..TAU_REPS {
        let id = s.alloc_id();
        let t = Instant::now();
        s.queue(REALPATH, &Enc::new().u32(id).str(b".").done())
            .await?;
        s.flush().await?;
        let r = s.recv().await?;
        ensure!(r.id == id, "reply id {} does not match request {id}", r.id);
        samples.push(t.elapsed());
    }
    samples.sort_unstable();
    Ok(samples[samples.len() / 2])
}

/// One READDIR sweep carries every entry's attrs, which is what lets the origin
/// layer skip per-file STAT entirely and keep invariant 1 within reach.
async fn list(s: &mut Session, dir: &str) -> Result<Vec<(String, Attrs)>> {
    let id = s.alloc_id();
    s.queue(OPENDIR, &Enc::new().u32(id).str(dir.as_bytes()).done())
        .await?;
    s.flush().await?;
    let r = s.recv().await?;
    ensure!(
        r.kind == HANDLE,
        "opendir {dir} refused (reply type {})",
        r.kind
    );
    let handle = Dec::new(r.payload())
        .str()
        .context("opendir handle")?
        .to_vec();

    let mut out = Vec::new();
    loop {
        let id = s.alloc_id();
        s.queue(READDIR, &Enc::new().u32(id).str(&handle).done())
            .await?;
        s.flush().await?;
        let r = s.recv().await?;
        if r.kind == STATUS {
            break;
        }
        ensure!(r.kind == NAME, "readdir gave reply type {}", r.kind);
        let mut d = Dec::new(r.payload());
        let count = d.u32().context("readdir count")?;
        for _ in 0..count {
            let name = String::from_utf8_lossy(d.str().context("filename")?).into_owned();
            d.str().context("longname")?;
            let attrs = Attrs::decode(&mut d).context("attrs")?;
            out.push((name, attrs));
        }
    }

    let id = s.alloc_id();
    s.queue(CLOSE, &Enc::new().u32(id).str(&handle).done())
        .await?;
    s.flush().await?;
    s.recv().await?;
    Ok(out)
}

async fn batch_open(s: &mut Session, paths: &[String]) -> Result<(Duration, Vec<Vec<u8>>)> {
    let t = Instant::now();
    for p in paths {
        let id = s.alloc_id();
        s.queue(
            OPEN,
            &Enc::new()
                .u32(id)
                .str(p.as_bytes())
                .u32(FXF_READ)
                .u32(0)
                .done(),
        )
        .await?;
    }
    s.flush().await?;

    let mut handles = Vec::with_capacity(paths.len());
    for _ in 0..paths.len() {
        let r = s.recv().await?;
        ensure!(r.kind == HANDLE, "open refused (reply type {})", r.kind);
        handles.push(Dec::new(r.payload()).str().context("open handle")?.to_vec());
    }
    Ok((t.elapsed(), handles))
}

async fn batch_read(s: &mut Session, handles: &[Vec<u8>]) -> Result<(Duration, usize)> {
    let t = Instant::now();
    for h in handles {
        let id = s.alloc_id();
        s.queue(READ, &Enc::new().u32(id).str(h).u64(0).u32(READ_LEN).done())
            .await?;
    }
    s.flush().await?;

    let mut bytes = 0usize;
    for _ in 0..handles.len() {
        let r = s.recv().await?;
        match r.kind {
            DATA => bytes += Dec::new(r.payload()).str().map_or(0, |b| b.len()),
            STATUS => {}
            other => bail!("read gave reply type {other}"),
        }
    }
    Ok((t.elapsed(), bytes))
}

async fn batch_close(s: &mut Session, handles: &[Vec<u8>]) -> Result<()> {
    for h in handles {
        let id = s.alloc_id();
        s.queue(CLOSE, &Enc::new().u32(id).str(h).done()).await?;
    }
    s.flush().await?;
    for _ in 0..handles.len() {
        s.recv().await?;
    }
    Ok(())
}
