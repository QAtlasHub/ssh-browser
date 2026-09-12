//! Filesystem access shaped so that latency optimisation survives a backend swap.
//!
//! The operations are batch-first on purpose. A per-path interface — `stat(p)`,
//! `read(p)` — forces O(N) round trips no matter which backend implements it, so
//! the abstraction would defeat the invariant it sits beneath. A single read is
//! the n=1 case of `read_batch`, not the other way round.

use anyhow::{Result, anyhow};

use crate::sftp::wire::Attrs;

pub mod sftp;

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub attrs: Attrs,
    /// The owner's account name, when the listing reported one legibly.
    ///
    /// `None` means the remote did not say, or said it in a shape not worth guessing at —
    /// not that the file is unowned. Callers have to keep those two apart, because the one
    /// thing this feeds is the check on who wrote an annotation log.
    pub owner: Option<String>,
}

/// One byte range of one file.
#[derive(Debug, Clone)]
pub struct RangeReq {
    pub path: String,
    pub offset: u64,
    /// Bytes wanted. Fewer may come back at end of file, which is not an error.
    pub len: u64,
}

#[allow(async_fn_in_trait)]
pub trait RemoteFs {
    /// Read whole files. Implementations must issue every request before awaiting
    /// any reply; doing otherwise silently reintroduces O(N) round trips.
    async fn read_batch(&self, paths: &[String]) -> Vec<Result<Vec<u8>>>;

    /// Read byte ranges. Chunking is the implementation's business; what matters
    /// here is that the whole set is issued together, so a one-megabyte range costs
    /// one round trip rather than the thirty-two its chunks would suggest.
    async fn read_ranges(&self, reqs: &[RangeReq]) -> Vec<Result<Vec<u8>>>;

    /// List several directories at once. One listing carries every entry's attrs,
    /// which is what removes per-file stat from the page path; batching the
    /// listings is what holds a symlink check over a deep path at one round trip
    /// rather than one per path component.
    async fn list_dirs(&self, paths: &[String]) -> Vec<Result<Vec<Entry>>>;

    /// The n=1 case, defined in terms of the batch so that no implementation can
    /// quietly make the single listing the cheap path and the batch a loop.
    async fn list_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let one = [path.to_string()];
        self.list_dirs(&one)
            .await
            .into_iter()
            .next()
            .unwrap_or_else(|| Err(anyhow!("list_dirs returned no result for {path}")))
    }

    /// Append bytes to a file, creating it if absent.
    ///
    /// Append rather than write, and single rather than batched, because that is the
    /// only write this design needs and the only one that is safe without a lock. A log
    /// has exactly one writer by construction, so an append cannot interleave with
    /// anyone else's — which is precisely why the annotation format is per-author logs
    /// and not one shared file.
    async fn append(&self, path: &str, bytes: &[u8]) -> Result<()>;

    /// Create a directory and every missing parent.
    ///
    /// Every level is issued at once and per-level failures are ignored: a level that
    /// already exists reports one, and the only outcome that matters is whether the
    /// deepest level is there afterwards. Walking down a level per round trip would
    /// cost depth round trips for something that happens once per document.
    async fn mkdirs(&self, path: &str) -> Result<()>;

    /// Flushes issued so far. One flush is one remote round trip, so this is the
    /// invariant made observable, and assertable in tests.
    fn round_trips(&self) -> u64;
}
